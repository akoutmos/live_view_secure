defmodule LiveViewSecure.Test.Protocol.Client do
  @moduledoc false
  # A dumb websocket client: forwards every decoded frame to its owner and
  # sends whatever bytes it is told to. No LiveView JS semantics at all.
  use WebSockex

  def start(url, cookie, owner) do
    WebSockex.start(url, __MODULE__, %{owner: owner}, extra_headers: [{"cookie", cookie}])
  end

  def send_text(pid, text), do: WebSockex.send_frame(pid, {:text, text})

  @impl true
  def handle_frame({:text, text}, %{owner: owner} = state) do
    send(owner, {:ws, self(), Jason.decode!(text)})
    {:ok, state}
  end

  def handle_frame(_frame, state), do: {:ok, state}

  @impl true
  def handle_disconnect(_status, %{owner: owner} = state) do
    send(owner, {:ws_closed, self()})
    {:ok, state}
  end
end

defmodule LiveViewSecure.Test.Protocol.Recorder do
  @moduledoc false
  # Handlers in the wire fixtures call record/2, so a test can tell whether a
  # handler ran without trusting anything the LiveView sends back.
  use Agent

  def start_link(_), do: Agent.start_link(fn -> [] end, name: __MODULE__)

  def record(where, event, params) do
    if Process.whereis(__MODULE__) do
      Agent.update(__MODULE__, &[{where, event, params} | &1])
    end

    :ok
  end

  def reset, do: Agent.update(__MODULE__, fn _ -> [] end)
  def all, do: __MODULE__ |> Agent.get(& &1) |> Enum.reverse()
end

defmodule LiveViewSecure.Test.Protocol.Wire do
  @moduledoc false
  # Drives a real Phoenix.LiveView.Socket over a real websocket (Bandit +
  # WebSockex), speaking the V2 JSON protocol by hand:
  #
  #     [join_ref, ref, topic, event, payload]
  #
  # The dead render is fetched over real HTTP (:httpc), so the session token,
  # static token, CSRF token and session cookie are exactly what a browser
  # (or an attacker with their own account) gets.
  import ExUnit.Assertions

  alias LiveViewSecure.Test.Protocol.Client

  @derive {Inspect, only: [:topic, :ref]}
  defstruct [:ws, :topic, :join_ref, :page, rendered: %{}, ref: 100]

  @timeout 2_000

  ## HTTP

  def get_page!(port, path) do
    url = "http://localhost:#{port}#{path}"
    {200, headers, body} = http_get!(port, path)

    cookie =
      for {"set-cookie", v} <- headers do
        v |> String.split(";") |> hd()
      end
      |> Enum.join("; ")

    doc = LazyHTML.from_document(body)
    [csrf] = doc |> LazyHTML.query("meta[name=csrf-token]") |> LazyHTML.attribute("content")
    main = LazyHTML.query(doc, "[data-phx-main]")

    %{
      port: port,
      url: url,
      cookie: cookie,
      csrf: csrf,
      id: one_attr(main, "id"),
      session: one_attr(main, "data-phx-session"),
      static: one_attr(main, "data-phx-static"),
      doc: doc
    }
  end

  @doc "Status code of a plain GET (used to detect a dead render that refuses to render)."
  def http_status(port, path), do: port |> http_get!(path) |> elem(0)

  # Minimal HTTP/1.1 GET over a raw TCP socket (no client library needed).
  def http_get!(port, path) do
    {:ok, sock} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        sock,
        "GET #{path} HTTP/1.1\r\nhost: localhost:#{port}\r\naccept: text/html\r\n" <>
          "connection: close\r\n\r\n"
      )

    raw = recv_all(sock, [])
    [head, body] = String.split(raw, "\r\n\r\n", parts: 2)
    ["HTTP/1.1 " <> status_line | header_lines] = String.split(head, "\r\n")
    {status, _} = Integer.parse(status_line)

    headers =
      for line <- header_lines do
        [k, v] = String.split(line, ":", parts: 2)
        {String.downcase(k), String.trim(v)}
      end

    body =
      if {"transfer-encoding", "chunked"} in headers, do: dechunk(body, []), else: body

    {status, headers, body}
  end

  defp recv_all(sock, acc) do
    case :gen_tcp.recv(sock, 0, 2_000) do
      {:ok, data} -> recv_all(sock, [acc | data])
      {:error, :closed} -> IO.iodata_to_binary(acc)
    end
  end

  defp dechunk(data, acc) do
    [size_hex, rest] = String.split(data, "\r\n", parts: 2)

    case Integer.parse(size_hex, 16) do
      {0, _} ->
        IO.iodata_to_binary(acc)

      {size, _} ->
        <<chunk::binary-size(^size), "\r\n", rest::binary>> = rest
        dechunk(rest, [acc | chunk])
    end
  end

  defp one_attr(lazy, name) do
    [value] = LazyHTML.attribute(lazy, name)
    value
  end

  ## Websocket

  def connect!(page) do
    query = URI.encode_query(%{"_csrf_token" => page.csrf, "vsn" => "2.0.0"})
    url = "ws://localhost:#{page.port}/live/websocket?" <> query
    {:ok, ws} = Client.start(url, page.cookie, self())
    ws
  end

  @doc "Opens a page over HTTP, connects a websocket and joins the main LiveView."
  def open!(port, path, opts \\ []) do
    page = get_page!(port, path)
    ws = connect!(page)

    case join(ws, page, opts) do
      {:ok, conn} -> conn
      {:error, reply} -> flunk("join failed: #{inspect(reply)}")
    end
  end

  def default_join_payload(page) do
    %{
      "url" => page.url,
      "params" => %{
        "_csrf_token" => page.csrf,
        "_mounts" => 0,
        "_mount_attempts" => 0,
        "_track_static" => []
      },
      "session" => page.session,
      "static" => page.static,
      "sticky" => false
    }
  end

  @doc """
  Joins `lv:<id>`. `opts[:payload]` can rewrite the join payload, which is how
  the tests send joins a browser wouldn't.
  """
  def join(ws, page, opts \\ []) do
    topic = Keyword.get(opts, :topic, "lv:" <> page.id)
    payload = default_join_payload(page)
    payload = if fun = opts[:payload], do: fun.(payload), else: payload
    join_ref = "1"
    send_msg(ws, [join_ref, join_ref, topic, "phx_join", payload])

    case await(ws, topic, join_ref) do
      {:reply, %{"status" => "ok", "response" => %{"rendered" => rendered}}} ->
        conn = %__MODULE__{ws: ws, topic: topic, join_ref: join_ref, page: page}
        {:ok, merge(conn, rendered)}

      other ->
        {:error, other}
    end
  end

  @doc "Joins a nested (live_render) child, found in the parent's rendered HTML."
  def join_child(%__MODULE__{} = parent, child_id, opts \\ []) do
    [el] = parent |> html() |> LazyHTML.query("##{child_id}") |> Enum.to_list()

    page = %{
      parent.page
      | id: child_id,
        session: one_attr(el, "data-phx-session"),
        # Like the JS client's getStatic(): an empty attribute is sent as null.
        static:
          if(one_attr(el, "data-phx-static") == "",
            do: nil,
            else: one_attr(el, "data-phx-static")
          )
    }

    payload_fun = fn payload ->
      payload = payload |> Map.delete("url") |> Map.put("static", page.static)
      if f = opts[:payload], do: f.(payload), else: payload
    end

    join(parent.ws, page, Keyword.put(opts, :payload, payload_fun))
  end

  @doc """
  Sends `payload` as an "event" message on the LiveView's topic and waits for
  the outcome. Returns `{result, conn}` where result is `{:ok, reply_payload}`,
  `{:error, reply_payload}` or `:crashed` (the LiveView process died).
  """
  def push(%__MODULE__{} = conn, event \\ "event", payload) do
    ref = Integer.to_string(conn.ref)
    conn = %{conn | ref: conn.ref + 1}
    send_msg(conn.ws, [conn.join_ref, ref, conn.topic, event, payload])

    case await(conn.ws, conn.topic, ref) do
      {:reply, %{"status" => "ok", "response" => response}} ->
        conn = if diff = response["diff"], do: merge(conn, diff), else: conn
        {{:ok, response}, conn}

      {:reply, %{"status" => status, "response" => response}} ->
        {{String.to_atom(status), response}, conn}

      :crashed ->
        {:crashed, conn}
    end
  end

  @doc """
  Sends every payload as an "event" frame back to back, without waiting for
  replies in between (what a client can do with pipelined frames), then
  collects the outcome of each, in order. Returns `{results, conn}`.
  """
  def pipeline(%__MODULE__{} = conn, payloads) do
    {refs, conn} =
      Enum.map_reduce(payloads, conn, fn payload, conn ->
        ref = Integer.to_string(conn.ref)
        send_msg(conn.ws, [conn.join_ref, ref, conn.topic, "event", payload])
        {ref, %{conn | ref: conn.ref + 1}}
      end)

    # Once the LiveView dies, the frames still queued behind it get no reply.
    {results, {conn, _dead?}} =
      Enum.map_reduce(refs, {conn, false}, fn
        _ref, {conn, true} ->
          {:crashed, {conn, true}}

        ref, {conn, false} ->
          case await(conn.ws, conn.topic, ref) do
            {:reply, %{"status" => "ok", "response" => response}} ->
              conn = if diff = response["diff"], do: merge(conn, diff), else: conn
              {{:ok, response}, {conn, false}}

            {:reply, %{"status" => status, "response" => response}} ->
              {{String.to_atom(status), response}, {conn, false}}

            :crashed ->
              {:crashed, {conn, true}}
          end
      end)

    {results, conn}
  end

  @doc "Diffs the server pushes on its own (not as a reply) within `ms`."
  def unsolicited_diffs(%__MODULE__{ws: ws, topic: topic}, ms \\ 300),
    do: collect_diffs(ws, topic, ms)

  defp collect_diffs(ws, topic, ms) do
    receive do
      {:ws, ^ws, [_, nil, ^topic, "diff", diff]} -> [diff | collect_diffs(ws, topic, ms)]
    after
      ms -> []
    end
  end

  @doc "Convenience: a click-style event with a JSON map/any value."
  def event(conn, type, event, value, extra \\ %{}) do
    push(conn, Map.merge(%{"type" => type, "event" => event, "value" => value}, extra))
  end

  def send_msg(ws, msg), do: :ok = Client.send_text(ws, Jason.encode!(msg))

  @doc "Waits for the reply to `ref` on `topic` (or for the LiveView to die)."
  def await(ws, topic, ref) do
    receive do
      {:ws, ^ws, [_join_ref, ^ref, ^topic, "phx_reply", payload]} ->
        {:reply, payload}

      {:ws, ^ws, [_join_ref, _ref, ^topic, "phx_error", _payload]} ->
        :crashed

      {:ws, ^ws, [_join_ref, _ref, ^topic, "phx_close", _payload]} ->
        :crashed

      {:ws_closed, ^ws} ->
        :crashed
    after
      @timeout -> flunk("no reply to ref #{ref} on #{topic}")
    end
  end

  @doc "Drains pushed (non-reply) diffs for this topic into the rendered state."
  def sync(%__MODULE__{} = conn) do
    receive do
      {:ws, ws, [_, nil, topic, "diff", diff]} when ws == conn.ws and topic == conn.topic ->
        conn |> merge(diff) |> sync()
    after
      50 -> conn
    end
  end

  ## Rendering (the server's diff -> HTML, like the JS client does)

  def html(%__MODULE__{rendered: rendered}) do
    rendered
    |> Phoenix.LiveView.Diff.to_iodata(&add_cid_attr/2)
    |> IO.iodata_to_binary()
    |> LazyHTML.from_fragment()
  end

  def query(conn, selector), do: conn |> html() |> LazyHTML.query(selector)

  def attr(conn, selector, name) do
    case conn |> query(selector) |> LazyHTML.attribute(name) do
      [value] -> value
      other -> flunk("expected one #{selector}[#{name}], got #{inspect(other)}")
    end
  end

  def text(conn, selector), do: conn |> query(selector) |> LazyHTML.text()

  @doc "The data-phx-component cid of the component whose root matches selector."
  def cid(conn, selector), do: conn |> attr(selector, "data-phx-component") |> String.to_integer()

  @doc "The params a signed phx-click button would send (phx-value-* attributes)."
  def phx_values(conn, selector) do
    [el] = conn |> query(selector) |> Enum.to_list()

    for {"phx-value-" <> key, value} <- el |> LazyHTML.to_tree() |> attrs(), into: %{} do
      {key, value}
    end
  end

  defp attrs([{_tag, attrs, _children}]), do: attrs

  @doc "The `value` of the first push op in a JS command attribute."
  def pushed(conn, selector, attr \\ "phx-click") do
    [["push", %{"event" => event} = args] | _] = conn |> attr(selector, attr) |> Jason.decode!()
    {event, Map.get(args, "value", %{})}
  end

  defp merge(conn, diff) do
    %{conn | rendered: Phoenix.LiveViewTest.Diff.merge_diff(conn.rendered, atomize(diff))}
  end

  defp add_cid_attr(cid, [head | tail]) do
    head =
      Regex.replace(
        ~r/^(\s*(?:<!--.*?-->\s*)*)<([^\s\/>]+)/,
        IO.iodata_to_binary(head),
        "\\0 data-phx-component=\"#{cid}\"",
        global: false
      )

    [head | tail]
  end

  # JSON turned the diff's integer and atom keys into strings. Undo that.
  @atom_keys ~w(s c k kc km e r t p stream)
  defp atomize(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {atomize_key(k), atomize(v)} end)
  end

  defp atomize(list) when is_list(list), do: Enum.map(list, &atomize/1)
  defp atomize(other), do: other

  defp atomize_key(k) when k in @atom_keys, do: String.to_existing_atom(k)

  defp atomize_key(k) when is_binary(k) do
    case Integer.parse(k) do
      {int, ""} -> int
      _ -> k
    end
  end
end

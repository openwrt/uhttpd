function handle_request(env)
	uhttpd.send("Status: 200 OK\r\n")
	uhttpd.send("Content-Type: text/html\r\n\r\n")

	uhttpd.send("<h1>Headers</h1>\n")
	for k, v in pairs(env.headers) do
		uhttpd.send(string.format("<strong>%s</strong>: %s<br>\n", k, v))
	end

	uhttpd.send("<h1>Environment</h1>\n")
	for k, v in pairs(env) do
		if type(v) == "string" then
			uhttpd.send(string.format("<code>%s=%s</code><br>\n", k, v))
		end
	end
end

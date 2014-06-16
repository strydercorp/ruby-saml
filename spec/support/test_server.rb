require 'socket'
require 'net/http'

class TestServer
  class << self
    def start(port)
      @port = port
      @requests = []
      @process = Process.fork {
        @server = TCPServer.open(port)
        work
      }
    end

    def stop
      Process.kill("TERM", @process)
    end

    def get(path)
      Net::HTTP.get_response(URI("http://127.0.0.1:#{@port}#{path}"))
    end

    def requests
      get('/requests').body.split("\n")
    end

    def reset
      get('/reset')
    end

    def work
      loop do
        socket = @server.accept

        request = socket.gets
        response = process(request)

        socket.print([
          "HTTP/1.1 200 OK",
          "Content-Type: application/xml",
          "Content-Length: #{response.bytesize}",
          "Connection: close",
          "",
          response
        ].join("\r\n"))

        socket.close
      end
    end

    private

    def process(request)
      _, path, _ = request.split(' ')

      case path
      when '/requests'
        @requests.join("\n")
      when '/reset'
        @requests = []
        '<status>OK</status>'
      when '/exploit'
        <<-RESPONSE
<!DOCTYPE Response [<!ENTITY file PUBLIC 'p' 'file:///etc/hostname'>]>
<Response>&file;</Response>
        RESPONSE
      else
        @requests << request.chomp
        '<status>RECORDED</status>'
      end
    end
  end
end

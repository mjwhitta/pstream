class PStream::CipherNegotiation
    attr_accessor :length
    attr_accessor :suite
    attr_accessor :suites

    attr_reader :dst
    attr_reader :ipv
    attr_reader :pstream
    attr_reader :src

    def colorize_hosts(src, dst)
        return "#{src} <-> #{dst}" if (!PStream.colorize?)
        return "#{src} <-> #{dst}".light_cyan
    end

    def colorize_ipv(ipv)
        return "IPv#{ipv}" if (!PStream.colorize?)
        return "IPv#{ipv}".light_cyan
    end

    def colorize_selected_suite(suite)
        return [
            "Selected".light_blue,
            @pstream.colorize_cipher_suite(suite),
            "from:".light_blue
        ].join(" ")
    end

    def initialize(pstream, ipv, src, dst)
        @dst = dst
        @ipv = ipv
        @length = nil
        @pstream = pstream
        @src = src
        @suite = nil
        @suites = Array.new
    end

    def summary
        ret = Array.new
        ret.push(
            "#{colorize_ipv(@ipv)} #{colorize_hosts(@src, @dst)}"
        )
        ret.push("    #{colorize_selected_suite(@suite)}") if (@suite)
        @suites.each do |suite|
            ret.push("    #{@pstream.colorize_cipher_suite(suite)}")
        end

        return ret.join("\n")
    end

    def to_s
        return summary
    end
end

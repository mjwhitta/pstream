require "hilighter"

class PStream::CipherNegotiation
    attr_accessor :length
    attr_accessor :suite
    attr_accessor :suites

    attr_reader :dst
    attr_reader :ipv
    attr_reader :pstream
    attr_reader :src

    def hilight_hosts(src, dst)
        return "#{src} <-> #{dst}" if (!PStream.hilight?)
        return "#{src} <-> #{dst}".light_cyan
    end
    private :hilight_hosts

    def hilight_ipv(ipv)
        return "IPv#{ipv}" if (!PStream.hilight?)
        return "IPv#{ipv}".light_cyan
    end
    private :hilight_ipv

    def hilight_selected_suite(suite)
        return [
            "Selected".light_blue,
            @pstream.hilight_cipher_suite(suite),
            "from:".light_blue
        ].join(" ")
    end
    private :hilight_selected_suite

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
            "#{hilight_ipv(@ipv)} #{hilight_hosts(@src, @dst)}"
        )
        ret.push("    #{hilight_selected_suite(@suite)}") if (@suite)
        @suites.each do |suite|
            ret.push("    #{@pstream.hilight_cipher_suite(suite)}")
        end

        return ret.join("\n")
    end

    def to_s
        return summary
    end
end

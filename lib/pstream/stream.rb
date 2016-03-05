class PStream::Stream
    attr_reader :desc
    attr_reader :frames
    attr_reader :id

    def colorize_address(address)
        return address if (!@colorize)
        return address.light_blue
    end

    def colorize_ascii(ascii)
        return ascii if (!@colorize)
        return ascii.light_white
    end

    def colorize_hex(hex)
        return hex if (!@colorize)
        return hex.light_green
    end

    def contents
        case @prot
        when /^tcp$/i
            stream=@id
        when /^udp$/i
            stream=@desc.gsub(" <-> ", ",")
        else
            raise PStream::Error::ProtocolNotSupported.new(@prot)
        end

        ret = Array.new
        %x(
            tshark -r #{@pcap} -z follow,#{@prot},hex,#{stream} | \
                 sed "s|^	||" | \grep -E "^[0-9A-Fa-f]{8}"
        ).split("\n").each do |line|
            m = line.match(/([0-9A-Fa-f]{8}) (.*) (.{17})/)
            ret.push(
                [
                    colorize_address(m[1]),
                    colorize_hex(m[2]),
                    colorize_ascii(m[3])
                ].join(" ")
            )
        end

        return ret.join("\n")
    end

    def initialize(pcap, prot, id, desc, frames, colorize = false)
        @colorize = colorize
        @desc = desc
        @frames = frames
        @id = id
        @pcap = pcap
        @prot = prot
    end

    def to_s
        return contents
    end
end

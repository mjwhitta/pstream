require "hilighter"

class PStream::Stream
    attr_reader :desc
    attr_reader :frames
    attr_reader :id

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
                    hilight_address(m[1]),
                    hilight_hex(m[2]),
                    hilight_ascii(m[3])
                ].join(" ")
            )
        end

        return ret.join("\n")
    end

    def hilight_address(address)
        return address if (!PStream.hilight?)
        return address.light_blue
    end
    private :hilight_address

    def hilight_ascii(ascii)
        return ascii if (!PStream.hilight?)
        return ascii.light_white
    end
    private :hilight_ascii

    def hilight_hex(hex)
        return hex if (!PStream.hilight?)
        return hex.light_green
    end
    private :hilight_hex

    def initialize(pcap, prot, id, desc, frames)
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

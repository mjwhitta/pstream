class PStream::Stream
    attr_reader :desc
    attr_reader :frames
    attr_reader :id

    def contents
        case @prot
        when /^tcp$/i
            id=@id
        when /^udp$/i
            id=@desc.gsub(" <-> ", ",")
        else
            raise PStream::Error::ProtocolNotSupported.new(@prot)
        end

        out = %x(
            tshark -r #{@pcap} -z follow,#{@prot},hex,#{id} | \
                 sed "s|^	||" | \grep -E "^[0-9A-Fa-f]{8}"
        )
        return out
    end

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

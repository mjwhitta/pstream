class PStream::Stream
    attr_accessor :desc
    attr_accessor :frames
    attr_accessor :id

    def contents
        out = %x(
            tshark -r #{@pcap} -z follow,#{@prot},hex,#{@id} | \
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

    def to_s()
        return contents
    end
end

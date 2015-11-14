require "pathname"
require "scoobydoo"

class PStream
    attr_accessor :tcp_streams
    attr_accessor :udp_streams

    def ciphers
        # List ciphers during ssl handshake
        out = %x(
            tshark -r #{@pcap} -Y ssl.handshake.ciphersuite -V | \
                 \grep -E "Internet Protocol|Hostname:|Cipher Suite"
        )
        return out
    end

    def get_streams(prot)
        streams = Array.new

        out = %x(
            tshark -r #{@pcap} -z conv,#{prot} | \grep -E "<->" | \
                awk '{print $1, $2, $3, "|", $8, "Frames"}'
        )

        count = 0
        out.split("\n").each do |line|
            desc, frames = line.split(" | ")

            id = count
            id = desc.gsub(" <-> ", ",") if (prot == "udp")

            streams.push(Stream.new(@pcap, prot, id, desc, frames))
            count += 1
        end

        return streams
    end
    private :get_streams

    def initialize(pcap)
        if (ScoobyDoo.where_are_you("tshark").nil?)
            raise PStream::Error::TsharkNotFound.new
        end

        @pcap = Pathname.new(pcap).expand_path

        if (!@pcap.exist?)
            raise PStream::Error::PcapNotFound.new(@pcap)
        elsif (!@pcap.readable?)
            raise PStream::Error::PcapNotReadable.new(@pcap)
        end

        @tcp_streams = get_streams("tcp")
        @udp_streams = get_streams("udp")
    end

    def summary
        ret = Array.new

        # List TCP streams
        ret.push("TCP Streams:")
        count = 0
        @tcp_streams.each do |stream|
            ret.push("#{count} | #{stream.desc} | #{stream.frames}")
            count += 1
        end
        ret.push("")

        # List UDP streams
        ret.push("UDP Streams:")
        count = 0
        @udp_streams.each do |stream|
            ret.push("#{count} | #{stream.desc} | #{stream.frames}")
            count += 1
        end
        ret.push("")

        # List ciphers that were actually selected
        ret.push("Ciphers in use:")
        f = "ssl.handshake.ciphersuite && ssl.handshake.type == 2"
        out = %x(
            tshark -r #{@pcap} -Y "#{f}" -V | \
                \grep -E "Cipher Suite:" | \
                sed -r "s|^ +Cipher Suite: ||g" | sort -u
        )
        ret.concat(out.split("\n"))

        return ret.join("\n")
    end

    def to_s
        return summary
    end
end

require "pstream/error"
require "pstream/stream"

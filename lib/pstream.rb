require "pathname"
require "scoobydoo"

class PStream
    attr_reader :streams

    def ciphers
        # List ciphers during ssl handshake
        out = %x(
            tshark -r #{@pcap} -Y ssl.handshake.ciphersuite -V 2>&1 \
                | \grep -E "Internet Protocol|Hostname:|Cipher Suite"
        )
        return out
    end

    def get_stream(stream, prot = "tcp")
        case prot
        when /^tcp$/i
            if (@streams["tcp"].empty? && !@streams["udp"].empty?)
                return get_stream(stream, "udp")
            end
            if (stream >= @streams["tcp"].length)
                if (stream < @streams["udp"].length)
                    return @streams["udp"][stream]
                end
                raise PStream::Error::StreamNotFound.new(stream, prot)
            end
            return @streams["tcp"][stream]
        when /^udp$/i
            if (@streams["udp"].empty? && !@streams["tcp"].empty?)
                return get_stream(stream, "tcp")
            end
            if (stream >= @streams["udp"].length)
                if (stream < @streams["tcp"].length)
                    return @streams["tcp"][stream]
                end
                raise PStream::Error::StreamNotFound.new(stream, prot)
            end
            return @streams["udp"][stream]
        else
            raise PStream::Error::ProtocolNotSupported.new(prot)
        end
    end

    def get_streams(prot)
        case prot
        when /^tcp$/i, /^udp$/i
            # Do nothing
        else
            raise PStream::Error::ProtocolNotSupported.new(prot)
        end

        streams = Array.new

        out = %x(
            tshark -r #{@pcap} -z conv,#{prot} 2>&1 | \grep -E "<->" \
                | awk '{print $1, $2, $3, "|", $8, "Frames"}'
        )

        count = 0
        out.split("\n").each do |line|
            desc, frames = line.split(" | ")
            streams.push(Stream.new(@pcap, prot, count, desc, frames))
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

        @streams = Hash.new
        ["tcp", "udp"].each do |prot|
            @streams[prot] = get_streams(prot)
        end
    end

    def negotiated_ciphers
        f = "ssl.handshake.ciphersuite && ssl.handshake.type == 2"
        out = %x(
            tshark -r #{@pcap} -Y "#{f}" -V 2>&1 | \
                \grep -E "Cipher Suite:" | \
                sed -r "s|^ +Cipher Suite: ||g" | sort -u
        )
        return out.split("\n")
    end

    def summary
        ret = Array.new

        # List streams
        ["tcp", "udp"].each do |prot|
            ret.push("#{prot} streams:")
            @streams[prot].each do |s|
                ret.push("#{s.id} | #{s.desc} | #{s.frames}")
            end
            ret.push("")
        end

        # List ciphers that were actually selected
        ret.push("Ciphers in use:")
        ret.concat(negotiated_ciphers)

        return ret.join("\n")
    end
    private :summary

    def to_s
        return summary
    end
end

require "pstream/error"
require "pstream/stream"

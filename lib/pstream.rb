require "hilighter"
require "pathname"
require "scoobydoo"

class PStream
    attr_reader :streams

    def cipher_negotiations
        negotiations = Hash.new
        negotiation = nil
        hello = nil

        # List ciphers during ssl handshake
        %x(
            tshark -r #{@pcap} -Y ssl.handshake.ciphersuite -V 2>&1 \
                | \grep -E "(Handshake|Internet) Prot|Cipher Suite"
        ).split("\n").each do |line|
            case line.gsub(/^ +/, "")
            when /^Cipher Suite:/
                m = line.match(/Cipher Suite: ([^ ]+) (.*)$/)
                case hello
                when "Client"
                    case m[1]
                    when "Unknown"
                        negotiation.suites.push("#{m[1]} #{m[2]}")
                    else
                        negotiation.suites.push(m[1])
                    end
                when "Server"
                    id = "#{negotiation.dst} <-> #{negotiation.src}"
                    # Ignore partial handshakes that are server side
                    # only
                    if (negotiations[id])
                        case m[1]
                        when "Unknown"
                            negotiations[id].suite = "#{m[1]} #{m[2]}"
                        else
                            negotiations[id].suite = m[1]
                        end
                    end
                    negotiation = nil
                end
            when /^Cipher Suites Length:/
                m = line.match(/Cipher Suites Length: ([0-9]+)$/)
                negotiation.length = m[1].to_i
            when /^Handshake Protocol: [^ ]+ Hello$/
                m = line.match(/Handshake Protocol: ([^ ]+) Hello$/)
                hello = m[1]
            when /^Handshake Protocol: Certificate$/
                # TODO extract cert info
            when /^Handshake Protocol: Server Key Exchange$/
                # TODO extract key info
            when /^Internet Protocol Version/
                if (negotiation)
                    id = "#{negotiation.src} <-> #{negotiation.dst}"
                    negotiations[id] = negotiation
                end

                m = line.gsub("Internet Protocol Version", "").match(
                    /(4|6), Src: ([^,]+), Dst: (.*)$/
                )

                ipv = m[1]
                src = m[2]
                dst = m[3]

                negotiation = PStream::CipherNegotiation.new(
                    self,
                    ipv,
                    src,
                    dst
                )
            end
        end

        # Keep parital handshakes that are client side only
        if (negotiation)
            id = "#{negotiation.src} <-> #{negotiation.dst}"
            negotiations[id] = negotiation
        end

        return negotiations.values
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

        count = 0
        %x(
            tshark -r #{@pcap} -z conv,#{prot} 2>&1 | \grep -E "<->" \
                | awk '{print $1, $2, $3, "|", $8, "Frames"}'
        ).split("\n").each do |line|
            desc, frames = line.split(" | ")
            streams.push(
                Stream.new(@pcap, prot, count, desc, frames)
            )
            count += 1
        end

        return streams
    end
    private :get_streams

    def self.hilight?
        @@hilight ||= false
        return @@hilight
    end

    def hilight_cipher_suite(suite)
        return suite if (!@@hilight)

        case suite
        when /Unknown/
            # Unknown
            return suite.light_yellow
        when /NULL|MD5|RC4|anon/
            # Bad cipher suites
            return suite.light_red
        when /E?(EC)?DHE?|AES_256/
            # Great cipher suites
            return  suite.light_green
        else
            # Maybe OK
            return  suite.light_white
        end
    end

    def hilight_header(header)
        return header if (!@@hilight)
        return header.light_cyan
    end
    private :hilight_header

    def hilight_stream(stream)
        if (!@@hilight)
            return "#{stream.id} | #{stream.desc} | #{stream.frames}"
        end
        return [
            "#{stream.id}".light_blue,
            stream.desc.light_green,
            stream.frames.light_white
        ].join(" | ")
    end
    private :hilight_stream

    def initialize(pcap, hilight = false)
        if (ScoobyDoo.where_are_you("tshark").nil?)
            raise PStream::Error::TsharkNotFound.new
        end

        @@hilight = hilight
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

    def summary
        ret = Array.new

        # List streams
        ["tcp", "udp"].each do |prot|
            ret.push(hilight_header("#{prot.upcase} streams:"))
            @streams[prot].each do |stream|
                ret.push(hilight_stream(stream))
            end
            ret.push("")
        end

        # List ciphers that were actually selected
        ret.push(hilight_header("Ciphers in use:"))
        cipher_negotiations.map do |negotiation|
            negotiation.suite
        end.uniq.each do |suite|
            ret.push(hilight_cipher_suite(suite))
        end

        return ret.join("\n")
    end
    private :summary

    def to_s
        return summary
    end
end

require "pstream/cipher_negotiation"
require "pstream/error"
require "pstream/stream"

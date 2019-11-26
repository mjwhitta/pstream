Gem::Specification.new do |s|
    s.add_development_dependency("rake", "~> 13.0", ">= 13.0.0")
    s.add_runtime_dependency("hilighter", "~> 1.5", ">= 1.5.1")
    s.add_runtime_dependency("scoobydoo", "~> 1.0", ">= 1.0.1")
    s.authors = ["Miles Whittaker"]
    s.date = Time.new.strftime("%Y-%m-%d")
    s.description = [
        "This ruby gem will summarize or extract info from pcap",
        "files."
    ].join(" ")
    s.email = "mj@whitta.dev"
    s.executables = Dir.chdir("bin") do
        Dir["*"]
    end
    s.files = Dir["lib/**/*.rb"]
    s.homepage = "https://gitlab.com/mjwhitta/pstream"
    s.license = "GPL-3.0"
    s.metadata = {
        "source_code_uri" => "https://gitlab.com/mjwhitta/hilighter/tree/ruby"
    }
    s.name = "pstream"
    s.summary = "Summarize or extract info from pcap files"
    s.version = "0.2.14"
end

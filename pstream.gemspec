Gem::Specification.new do |s|
    s.name = "pstream"
    s.version = "0.2.13"
    s.date = Time.new.strftime("%Y-%m-%d")
    s.summary = "Summarize or extract info from pcap files"
    s.description =
        "This ruby gem will summarize or extract info from pcap " \
        "files."
    s.authors = ["Miles Whittaker"]
    s.email = "mj@whitta.dev"
    s.executables = Dir.chdir("bin") do
        Dir["*"]
    end
    s.files = Dir["lib/**/*.rb"]
    s.homepage = "https://gitlab.com/mjwhitta/pstream"
    s.license = "GPL-3.0"
    s.add_development_dependency("rake", "~> 13.0", ">= 13.0.0")
    s.add_runtime_dependency("hilighter", "~> 1.3", ">= 1.3.0")
    s.add_runtime_dependency("scoobydoo", "~> 1.0", ">= 1.0.1")
end

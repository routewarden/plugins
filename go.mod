module github.com/routewarden/plugins

go 1.25.1

require (
	github.com/routewarden/tcp-warden v0.0.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/routewarden/tcp-warden => ../tcp-warden

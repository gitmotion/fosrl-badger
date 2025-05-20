# Badger Plugin for Traefik with Pangolin Integration

This is based on gitmotion/fosrl-badger, which is a fork of the original [Badger](https://github.com/fosrl/badger) plugin.
- This version is specifically designed to work with Pangolin to return the `CF-Connecting-IP`, `X-Real-IP`, and/or `X-Forwarded-For` headers to the pangolin.

Badger is a middleware plugin designed to work with the Traefik reverse proxy in conjunction with [Pangolin](https://github.com/fosrl/pangolin), a multi-tenant tunneled reverse proxy server and management interface with identity and access management. Badger acts as an authentication bouncer, ensuring only authenticated and authorized requests are allowed through the proxy.

This plugin is **required** to be configured alongside [Pangolin](https://github.com/fosrl/pangolin) to enforce secure authentication and session management.

## Installation

Learn how to set up [Pangolin](https://github.com/fosrl/pangolin) and Badger in the [Pangolin Documentation](https://github.com/fosrl/pangolin).

## Configuration

Badger requires the following configuration parameters to be specified in your [Traefik configuration file](https://doc.traefik.io/traefik/getting-started/configuration-overview/). These coincide with the separate [Pangolin](https://github.com/fosrl/pangolin) configuration file.

### Configuration Options

```yaml
apiBaseUrl: "http://localhost:3001/api/v1"
userSessionCookieName: "p_session_token"
resourceSessionRequestParam: "p_session_request"
trustedIps:
  - "173.245.48.0/20" # Cloudflare IP ranges start
  - "103.21.244.0/22"
  - "103.22.200.0/22"
  - "103.31.4.0/22"
  - "141.101.64.0/18"
  - "108.162.192.0/18"
  - "190.93.240.0/20"
  - "188.114.96.0/20"
  - "197.234.240.0/22"
  - "198.41.128.0/17"
  - "162.158.0.0/15"
  - "104.16.0.0/13"
  - "104.24.0.0/14"
  - "172.64.0.0/13"
  - "131.0.72.0/22"
  - "2400:cb00::/32"
  - "2606:4700::/32"
  - "2803:f800::/32"
  - "2405:b500::/32"
  - "2405:8100::/32" 
  - "2a06:98c0::/29" 
  - "2c0f:f248::/32" # Cloudflare IP ranges end
  - "10.0.0.1" # Single IP example
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

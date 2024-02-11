# tls-certificate-exporter
A Prometheus exporter to scrape certificates from remote connections to monitor the certificates

## Roadmap

- [ ] Configurable metrics prefix
- [ ] Support probe endpoint
- [ ] Better signal handling
    - Graceful shutdown
    - Cache clear
    - Configuration reload
- [ ] Support hot reloading
- [ ] Support STARTTLS
    - [ ] LDAP
    - [ ] SMTP
    - [ ] IMAP
    - [ ] POP3
    - [ ] FTP
    - [ ] XMPP
    - [ ] NNTP
    - [ ] PostgreSQL
    - [ ] MySQL

### Setup
1. <code>git clone https://github.com/meda10/Tor-simulations</code>
2. <code>cd Tor-simulations</code>
3. <code>git clone https://github.com/torps/torps</code>
4. <code>chown -R www-data:www-data "PATH_TO_DIRECTORY"/Tor-simulations/www/html</code> Docker container inherits file permissions
5. <code>htpasswd "PATH_TO_DIRECTORY"/Tor-simulations/nginx/password/.htpasswd "USERNAME"</code> Create user and password
5. <code>docker-compose up -d</code>

### Nginx configuration:
Config file  can be found in /Tor-simulations/nginx/config.d/default.conf
### Setup
1. <code>git clone https://github.com/meda10/Tor-simulations</code>
2. <code>cd Tor-simulations</code>
3. <code>git clone https://github.com/torps/torps</code>
4. <code>chown -R www-data:www-data "PATH_TO_DIRECTORY"/Tor-simulations/www/html</code> 
Docker container inherits file permissions
5. <code>htpasswd "PATH_TO_DIRECTORY"/Tor-simulations/nginx/password/.htpasswd "USERNAME"</code> Create user and password
5. <code>docker-compose up -d</code>

### Nginx configuration:
Config file  can be found in /Tor-simulations/nginx/config.d/default.conf




An image that includes Shadow along with the Tor plugin is available at [https://security.cs.georgetown.edu/shadow-docker-images/shadow-tor.tar.gz](https://security.cs.georgetown.edu/shadow-docker-images/shadow-tor.tar.gz).

To use these images:

1. Download the desired image (see above URLs).
2. Load it via: ```gunzip -c shadow-standalone.tar.gz | docker load```
3. Run it via: ```docker run -t -i -u shadow shadow-standalone /bin/bash```

(Replace *shadow-standalone* with *shadow-tor* if you are using the image with the Tor plugin.)

The **shadow** user has sudo access.  Its password is ***shadow***.
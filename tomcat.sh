{
useradd -m -U -d /opt/tomcat -s /bin/false tomcat || echo "User already exists."
cd /tmp
wget https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.62/bin/apache-tomcat-9.0.62.tar.gz
tar -xf apache-tomcat-9.0.62.tar.gz
mv apache-tomcat-9.0.62 /opt/tomcat/
ln -s /opt/tomcat/apache-tomcat-9.0.62 /opt/tomcat/latest
chown -R tomcat: /opt/tomcat
chmod +x /opt/tomcat/latest/bin/*.sh
cat <<EOF >/etc/systemd/system/tomcat.service
[Unit]
Description=Tomcat 9 servlet container
After=network.target

[Service]
Type=forking

User=tomcat
Group=tomcat

Environment="JAVA_HOME=/usr/lib/jvm/jre"
Environment="JAVA_OPTS=-Djava.security.egd=file:///dev/urandom"

Environment="CATALINA_BASE=/opt/tomcat/latest"
Environment="CATALINA_HOME=/opt/tomcat/latest"
Environment="CATALINA_PID=/opt/tomcat/latest/temp/tomcat.pid"
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"

ExecStart=/opt/tomcat/latest/bin/startup.sh
ExecStop=/opt/tomcat/latest/bin/shutdown.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tomcat
systemctl start tomcat ;} &
s_echo "n" "${Reset}-Installing tomcat...    "; spinner

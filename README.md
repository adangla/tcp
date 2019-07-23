# Check which python you use
`which python`

if you have
`/usr/bin/python`
then you must activate the virtual environment
`$ source ./venv/bin/activate`

if you have something similar to 
`/home/yona/work/tcom/tcp/venv/bin/python`
with `/home/yona/work/tcom/` replaced by your own path then your virtualenv is activated !

# Launch server
`sudo python demo_server.py`

# Launch client
`sudo python demo_client.py`

---
# TODO
- [x] 3-way handshake connexion in client side
- [x] 3-way handshake connexion in server side
- [ ] Replace send by sr1 in server side communication phase
- [x] print TCP state in connexion
- [ ] print TCP state in deconnexion
- [x] print received message
- [ ] Clean code
- [ ] Write close connexion
- [ ] Create config file
- [ ] Create Exeption to clearly close connexion when needed
- [x] Handle Timeout in communication phase in server side
- [ ] Handle Timeout in connexion phase in server side
- [ ] Handle Timeout in connexion phase in client side
- [ ] Remove useless TODO comment
- [ ] Create Exeption to manage Error states
- [ ] Check ACK and SEQ value in client connexion
- [ ] Check ACK and SEQ value in server connexion
- [ ] Check ACK and SEQ value in client communication
- [ ] Check ACK and SEQ value in server communication
- [ ] Improve CLI interface
- [ ] Call the correct errors in client
- [ ] Call the correct errors in server

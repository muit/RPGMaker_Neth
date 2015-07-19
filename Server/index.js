var net = require('net');
var port = 3000;

var server = net.createServer(function(socket){
  var name
  socket.on('data', function(data){
    var msg = data.toString();
    try{
      json = JSON.parse(msg);
      console.log(json);
    }
    catch(e){
      console.log(msg);
    }
  });
});
server.listen(port, function() {
  console.log("Listening on port "+port+"\n");
});

var Opcodes = {
  PLAYER_CONNECTED: 0,
  PLAYER_DISCONNECTED: 1
}
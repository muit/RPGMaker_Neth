#==============================================================================
# ** RPG Maker VX Ace - Nethwork API
#------------------------------------------------------------------------------
# Author: Muit (miguel_3c@hotmail.com)
#
# This work is protected by the following license:
# #----------------------------------------------------------------------------
# #  
# #  The MIT License (MIT)
# #
# # Copyright (c) 2014-2016 @muitxer (https://github.com/muit)
# #
# # Permission is hereby granted, free of charge, to any person obtaining
# # a copy of this software and associated documentation files (the "Software"),
# # to deal in the Software without restriction, including without limitation 
# # the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# # sell copies of the Software, and to permit persons to whom the Software
# # is furnished to do so, subject to the following conditions:
# #
# # The above copyright notice and this permission notice shall be included
# # in all copies or substantial portions of the Software.
# #
# # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# # IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
# # THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# #  
# #----------------------------------------------------------------------------
# 
#
# Parts of this project comes from:
# #:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=
# # RPG Maker XP Online System (RMX-OS)
# #------------------------------------------------------------------------------
# # Author: Blizzard
# #:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=:=
#


#==============================================================================
# ** Module Win32 - Handles numerical based data.
#------------------------------------------------------------------------------
# Author    Ruby
# Version   1.8.1
#==============================================================================

module Win32

  #----------------------------------------------------------------------------
  # ● Retrieves data from a pointer.
  #----------------------------------------------------------------------------
  def copymem(len)
    buf = "\0" * len
    Win32API.new('kernel32', 'RtlMoveMemory', 'ppl', '').call(buf, self, len)
    buf
  end
  
end

# Extends the numeric class.
class Numeric
  include Win32
end

# Extends the string class.
class String
  include Win32
end

#==============================================================================
# module Winsock
#------------------------------------------------------------------------------
# Serves as wrapper for the used Win32API Socket functions.
#==============================================================================

module Winsock

  DLL = 'ws2_32'

  Win32API_bind            = Win32API.new(DLL, 'bind', 'ppl', 'l')
  Win32API_closesocket     = Win32API.new(DLL, 'closesocket', 'p', 'l')
  Win32API_setsockopt      = Win32API.new(DLL, 'setsockopt', 'pllpl', 'l')
  Win32API_connect         = Win32API.new(DLL, 'connect', 'ppl', 'l')
  Win32API_gethostbyname   = Win32API.new(DLL, 'gethostbyname', 'p', 'l')
  Win32API_recv            = Win32API.new(DLL, 'recv', 'ppll', 'l')
  Win32API_select          = Win32API.new(DLL, 'select', 'lpppp', 'l')
  Win32API_send            = Win32API.new(DLL, 'send', 'ppll', 'l')
  Win32API_socket          = Win32API.new(DLL, 'socket', 'lll', 'l')
  Win32API_WSAGetLastError = Win32API.new(DLL, 'WSAGetLastError', '', 'l')
  
  def self.bind(*args);            Win32API_bind.call(*args);            end;
  def self.closesocket(*args);     Win32API_closesocket.call(*args);     end;
  def self.setsockopt(*args);      Win32API_setsockopt.call(*args);      end;
  def self.connect(*args);         Win32API_connect.call(*args);         end;
  def self.gethostbyname(*args);   Win32API_gethostbyname.call(*args);   end;
  def self.recv(*args);            Win32API_recv.call(*args);            end;
  def self.select(*args);          Win32API_select.call(*args);          end;
  def self.send(*args);            Win32API_send.call(*args);            end;
  def self.socket(*args);          Win32API_socket.call(*args);          end;
  def self.WSAGetLastError(*args); Win32API_WSAGetLastError.call(*args); end;
   
end

#==============================================================================
# Socket
#------------------------------------------------------------------------------
# Creates and manages sockets.
#==============================================================================

class Socket
  #----------------------------------------------------------------------------
  # ● Constants
  #----------------------------------------------------------------------------
  AF_UNSPEC                 = 0  
  AF_UNIX                   = 1
  AF_INET                   = 2
  AF_IPX                    = 6
  AF_APPLETALK              = 16

  PF_UNSPEC                 = 0  
  PF_UNIX                   = 1
  PF_INET                   = 2
  PF_IPX                    = 6
  PF_APPLETALK              = 16

  SOCK_STREAM               = 1
  SOCK_DGRAM                = 2
  SOCK_RAW                  = 3
  SOCK_RDM                  = 4
  SOCK_SEQPACKET            = 5
  
  IPPROTO_IP                = 0
  IPPROTO_ICMP              = 1
  IPPROTO_IGMP              = 2
  IPPROTO_GGP               = 3
  IPPROTO_TCP               = 6
  IPPROTO_PUP               = 12
  IPPROTO_UDP               = 17
  IPPROTO_IDP               = 22
  IPPROTO_ND                = 77
  IPPROTO_RAW               = 255
  IPPROTO_MAX               = 256

  SOL_SOCKET                = 65535
  
  SO_DEBUG                  = 1
  SO_REUSEADDR              = 4
  SO_KEEPALIVE              = 8
  SO_DONTROUTE              = 16
  SO_BROADCAST              = 32
  SO_LINGER                 = 128
  SO_OOBINLINE              = 256
  SO_RCVLOWAT               = 4100
  SO_SNDTIMEO               = 4101
  SO_RCVTIMEO               = 4102
  SO_ERROR                  = 4103
  SO_TYPE                   = 4104
  SO_SNDBUF                 = 4097
  SO_RCVBUF                 = 4098
  SO_SNDLOWAT               = 4099
  
  TCP_NODELAY               = 1
  
  MSG_OOB                   = 1
  MSG_PEEK                  = 2
  MSG_DONTROUTE             = 4
  
  IP_OPTIONS                = 1
  IP_DEFAULT_MULTICAST_LOOP = 1
  IP_DEFAULT_MULTICAST_TTL  = 1
  IP_MULTICAST_IF           = 2
  IP_MULTICAST_TTL          = 3
  IP_MULTICAST_LOOP         = 4
  IP_ADD_MEMBERSHIP         = 5
  IP_DROP_MEMBERSHIP        = 6
  IP_TTL                    = 7
  IP_TOS                    = 8
  IP_MAX_MEMBERSHIPS        = 20

  EAI_ADDRFAMILY            = 1
  EAI_AGAIN                 = 2
  EAI_BADFLAGS              = 3
  EAI_FAIL                  = 4
  EAI_FAMILY                = 5
  EAI_MEMORY                = 6
  EAI_NODATA                = 7
  EAI_NONAME                = 8
  EAI_SERVICE               = 9
  EAI_SOCKTYPE              = 10
  EAI_SYSTEM                = 11
  EAI_BADHINTS              = 12
  EAI_PROTOCOL              = 13
  EAI_MAX                   = 14

  AI_PASSIVE                = 1
  AI_CANONNAME              = 2
  AI_NUMERICHOST            = 4
  AI_MASK                   = 7
  AI_ALL                    = 256
  AI_V4MAPPED_CFG           = 512
  AI_ADDRCONFIG             = 1024
  AI_DEFAULT                = 1536
  AI_V4MAPPED               = 2048
  
  
  # set all accessible variables
  attr_reader :host
  attr_reader :port
  
  #----------------------------------------------------------------------------
  # Returns information about the given hostname.
  #----------------------------------------------------------------------------
  def self.gethostbyname(name)
    data = Winsock.gethostbyname(name)
    raise SocketError::ENOASSOCHOST if data == 0
    host = data.copymem(16).unpack('LLssL')
    name = host[0].copymem(256).unpack("c*").pack("c*").split("\0")[0]
    puts host.inspect
    address_type = host[2]
    address_list = host[4].copymem(4).unpack('L')[0].copymem(4).unpack("c*").pack("c*")
    return [name, [], address_type, address_list]
  end
  #----------------------------------------------------------------------------
  # Creates an INET-sockaddr struct.
  #----------------------------------------------------------------------------  
  def self.sockaddr_in(host, port)
    begin
      [AF_INET, port].pack('sn') + gethostbyname(host)[3] + [].pack('x8')
    rescue
      puts $!, $@
    end
  end
  #----------------------------------------------------------------------------
  # Creates a new socket and connects it to the given host and port.
  #----------------------------------------------------------------------------  
  def self.open(*args)
    socket = new(*args)
    if block_given?
      begin
        yield socket
      ensure
        socket.close
      end
    end
    return nil
  end
  #----------------------------------------------------------------------------
  # Creates a new socket.
  #----------------------------------------------------------------------------
  def initialize(domain, type, protocol)
    @descriptor = Winsock.socket(domain, type, protocol)
    SocketError.check if @descriptor == -1
    return @descriptor
  end
  #----------------------------------------------------------------------------
  # Binds a socket to the given sockaddr.
  #----------------------------------------------------------------------------
  def bind(sockaddr)
    result = Winsock.bind(@descriptor, sockaddr, sockaddr.size)
    SocketError.check if result == -1
    return result
  end
  #----------------------------------------------------------------------------
  # Closes a socket.
  #----------------------------------------------------------------------------
  def close
    result = Winsock.closesocket(@descriptor)
    SocketError.check if result == -1
    return result
  end
  #----------------------------------------------------------------------------
  # Connects a socket to the given sockaddr.
  #----------------------------------------------------------------------------
  def connect(host, port)
    @host, @port = host, port
    sockaddr = Socket.sockaddr_in(@host, @port)
    result = Winsock.connect(@descriptor, sockaddr, sockaddr.size)
    SocketError.check if result == -1
    return result
  end
  #----------------------------------------------------------------------------
  # Checks waiting data's status.
  #----------------------------------------------------------------------------
  def select(timeout)
    result = Winsock.select(1, [1, @descriptor].pack('ll'), 0, 0, [timeout, timeout * 1000000].pack('ll'))
    SocketError.check if result == -1
    return result
  end
  #----------------------------------------------------------------------------
  # Checks if data is waiting.
  #----------------------------------------------------------------------------
  def ready?
    return (self.select(0) != 0)
  end  
  #----------------------------------------------------------------------------
  # Returns recieved data.
  #----------------------------------------------------------------------------
  def recv(length, flags = 0)
    buffer = "\0" * length
    result = Winsock.recv(@descriptor, buffer, length, flags)
    SocketError.check if result == -1
    return '' if result == 0
    return buffer[0, result].unpack("c*").pack("c*") # gets rid of a bunch of \0
  end
  #----------------------------------------------------------------------------
  # Sends data to a host.
  #----------------------------------------------------------------------------
  def send(data, flags = 0)
    result = Winsock.send(@descriptor, data, data.size, flags)
    SocketError.check if result == -1
    return result
  end

  def sendPacket(packet)
    puts JSON.encode(packet.get_data)
    send(JSON.encode(packet.get_data));
  end
end

#==============================================================================
# TCPSocket
#------------------------------------------------------------------------------
# Represents a TCP Socket Connection.
#==============================================================================

class TCPSocket < Socket

  #----------------------------------------------------------------------------
  # Initialization.
  #  host - IP or URL of the hots
  #  port - port number
  #----------------------------------------------------------------------------
  def initialize(host = nil, port = nil)
    super(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    self.connect(host, port) if host != nil && port != nil
  end
  
end

#==============================================================================
# ** SocketError
#------------------------------------------------------------------------------
# Default exception class for sockets.
#==============================================================================

class SocketError < StandardError
  
  ENOASSOCHOST = 'getaddrinfo: no address associated with hostname.'
  
  def self.check
    errno = Winsock.WSAGetLastError
    raise Errno.const_get(Errno.constants.detect { |c| Errno.const_get(c).new.errno == errno })
  end
end


#==============================================================================
# ** Network Opcode
#------------------------------------------------------------------------------
# Packet identifier
#==============================================================================
class Opcode
  PLAYER_CONNECTED = 0
  PLAYER_DISCONNECTED = 1
end

#==============================================================================
# ** Network Packet
#------------------------------------------------------------------------------
# Contains information to be send or received
#==============================================================================
class Packet
  attr_reader :opcode
  attr_reader :data

  def initialize(opcode, data)
    @opcode = opcode
    @data = data
  end

  def get_data
    {:opcode => @opcode, :data => @data}
  end
end
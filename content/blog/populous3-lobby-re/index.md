+++
title = "Reverse engineering Populous: The Beginning's lobby networking"
date = 2024-01-14
+++

[Populous: The Beginning](https://en.wikipedia.org/wiki/Populous:_The_Beginning) is a PC game from 1998 I used to play when I was young so as a fun side project I decided to reverse engineer the network protocol used in the lobby and find some vulnerabilities in it. As a side note, all of this research happened more than 2 years ago but I finally decided to organize it.

It's an old game with the expectation of playing multiplayer in a LAN environment so there's not really a server and a player is selected as the host and takes the lobby management role. The game's lobby-related functionality is very basic, you select a lobby, called a session, to join from a list and, once you are in, there's basic information about other players, a chat and some game-related configuration options.

{{img(id="img/populous3_lobby.png" class="textCenter")}}

## Reconnaissance and analysis
My first step was getting the game from [GOG](https://www.gog.com/) for like 2€. Then I opened any executable file that seemed interesting in [IDA](https://hex-rays.com/) until I found *WEANETR.dll* which is responsible for all the networking-related functionality.

After opening the DLL in IDA I skimmed the code and quickly noticed there were calls to a logging function which was not part of the release. To get a better idea of the functionality in a dynamic way I wrote a [Frida](https://frida.re/) script to hook those logging calls and the *sendto/recvfrom* functions.
```javascript
var baseAddr = Module.findBaseAddress('WEANETR.dll');
console.log('WEANETR.dll baseAddr: ' + baseAddr);

var log_null_sub_3 = resolveAddress('0x10001020');

Interceptor.attach(log_null_sub_3, {
onEnter: function (args) {
var args_0 = args[0].readCString();
var split_args = args_0.split('%');
var print_string = split_args[0];
for (var i = 1; i < split_args.length; i++) {
    switch (split_args[i][0]) {
        case 's':
            print_string += args[i].readCString() + split_args[i].substring(1);
            break;
        case 'd':
            print_string += args[i].toInt32() + split_args[i].substring(1);
            break;
        default:
            print_string += '[Unknown format]' + args[i] + split_args[i].substring(1);
    }
}
console.log('[+] Log: ' + print_string.trim());
},
});

var sendto_wrapper = resolveAddress('0x10010850');
var recvfrom_wrapper = resolveAddress('0x100108B0');

Interceptor.attach(sendto_wrapper, {
    onEnter: function (args) {
        var local_port = swap16(ptr(args[0]).readU16());
        var to_port = swap16(ptr(args[1]).readU16());
        var to_ip_string = int2ip(swap32(ptr(args[1]).add(6).readU32()));
        console.log('[+] Sent: ' + local_port + ' --> ' + to_ip_string + ':' + to_port)
        console.log('[+] Return: ' + this.returnAddress + ' ThreadId: ' + this.threadId);
        console.log(hexdump(ptr(args[2]), {
            offset: 0,
            length: args[3].toInt32(),
            header: true,
            ansi: true
        }));
    },

});

Interceptor.attach(recvfrom_wrapper, { 
    onEnter: function (args) {
        this.recvbuf = ptr(args[0]);
        this.sock_obj = ptr(args[2])
        this.from_obj = ptr(args[3]);
    },
    onLeave: function (retval) {
        var from_port = swap16(this.from_obj.readU16());
        var from_ip_string = int2ip(swap32(this.from_obj.add(6).readU32()));
        var local_port = swap16(this.sock_obj.readU16());
        console.log('[+] Received: ' + local_port + ' <-- ' + from_ip_string + ':' + from_port);
        console.log('[+] Return: ' + this.returnAddress + ' ThreadId: ' + this.threadId);
        var recv_len = retval.toInt32();
        if (recv_len < 0) {
            console.log('Error: ' + recv_len);
        } else {
            console.log(hexdump(this.recvbuf, {
                offset: 0,
                length: recv_len,
                header: true,
                ansi: true
            }));
        }
    },
});
```
Now while interacting with the lobby I could see the output of each log and the packets being sent and received.

{{img(id="img/populous3_frida_output.png" class="textCenter")}}

After all of that, it was time to start reverse engineering for real.

## Reconstructing network related structures
This part is basically about reading decompiled code and understanding what it is doing, there's no secret, every function will give you a hint on what a structure is used for and that hint can help you understand a different function. I'm going to list some of the most relevant structures I reconstructed and add a comment about any interesting fields.

### Player's description
```c
struct PLAYERDESC
{
  wchar_t name[16];
  uint id;
  uint unknown;
  uint unknown2;
  uint unknown3;
  uint unknown4;
  byte flags;
  byte slot;
  uint ip;
  ushort port;
  char guid[16];
  char pad[3];
};
```
- **id**: derived from player slot.
- **flags**: has info about the player's status: ready, in-game, ...
- **slot**: position in the session.
- **guid**: generated from IP and date of connection.

### My player's description
```c
struct MYPLAYERDESC
{
  GAME_FLAGS flags;
  uint id;
  uint slot;
  char pad[33];
};
```
- **flags**: has info about my player's status: is hosting the game, is a player, in-game, ...

### Session's description
```c
struct SESSIONDESC
{
  uint game_verison;
  char session_guid[16];
  char game_guid[16];
  uint max_players;
  uint current_players;
  char unknown_guid[16];
  uint session_flags;
  uint language_id;
  uint unknown4;
  uint unknown5;
  uint unknown6;
  BF_Socket socket;
  char padding[10];
  wchar_t name[16];
  wchar_t unknown_pad[16];
};
```
- **game_version**: 1.1 base game or 1.2 with *Undiscovered Worlds* expansion.
- **game_guid**: identifies the game *Populous: The Beginning* since it looks like the network protocol is shared with *[Dungeon Keeper 2](https://en.wikipedia.org/wiki/Dungeon_Keeper_2)*.
- **session_flags**: info about the session such as: open to joining, has password, ...

### Network information
```c
struct NETWORKADDRESS
{
  char BF_Header[2];
  __int128 BFSGUID;
  char *IP_StringPTR;
  size_t IP_StringLength;
  ushort Port;
  char pad[4];
  ushort Zero;
  char IP_String;
};
```
- **BF_Header**: constant chars 'BF' probably identifies the company *[Bullfrog Productions](https://en.wikipedia.org/wiki/Bullfrog_Productions)*.
- **BFSGUID**: indicates what protocol stack to use but only supports UDP/IP.

### General game's network information
```c
struct NetworkServiceProvider
{
  NetworkServiceProvider_vtbl *__vftable /*VFT*/;
  int always_zero;
  CRITICAL_SECTION CriticalSection;
  int is_initialized;
  PLAYERDESC *player_list;
  uint host_id;
  void *callback_parse_packet;
  BF_NetworkAddress *networkAddress;
  char player_guid[16];
  __int128 game_guid;
  uint host_ip;
  ushort host_port;
  char pad3_2[280];
  HANDLE StartThread_event;
  HANDLE KillThread_event;
  HANDLE GuaranteedThread_event;
  HANDLE service_provider_thread;
  char pad4[4];
  SESSIONDESC sessiondesc;
  GAMEDESC game_desc;
  char pad5[457];
  wchar_t session_password[32];
  char *debug_server_struct;
  char *recv_buffer;
  uint last_player_id;
  LPWSADATA lpWSAData;
  BF_Socket recv_socket;
  char pad7[74];
};
```
- **callback_parse_packet**: callback to the function in the main executable responsible for in-game packet parsing.
- **debug_server_struct**: points to a debugging structure used for connectivity tests.
- **recv_buffer**: the buffer where the current network packet is stored.

### Network vtable
```c
struct /*VFT*/ NetworkServiceProvider_vtbl
{
  void *Initialize
  void *ShutDown;
  void *SetupConnection;
  void *EnumerateLocalServices;
  void *AreWeLobbied;
  void *EnumerateLobbyApplications;
  void *RunLobbyApplication;
  void *CreateSPSession;
  void *JoinSPSession;
  void *DestroySPSession;
  void *EnumerateSession;
  void *EnableNewPlayers;
  void *EnumeratePlayers;
  void *SendMessage;
  void *SendMessageTo;
  void *ReadSPMessage;
  void *ChangeHost;
  void *SendMSResults;
  void *EnumerateNetworkMediumsModem;
  void *EnumerateNetworkMediumsDPlay;
  void *CreateNetworkAddress;
  void *GetPlayerSlot;
  void *ParseDatagram;
};
```
- **EnumerateLobbyApplications, RunLobbyApplication, EnumeratePlayers, EnumerateNetworkMediumsModem & EnumerateNetworkMediumsDPlay**: not implemented for this protocol stack.
- **ReadSPMessage**: receives, parses and interpretes packets related to the lobby.
- **ParseDatagram**: receives in-game packets and sends them to the main executable.

These are all the main structures that I used to understand the code's functionality. Now let's move to the network packets used in this game, I decided to refer to the protocol as *BF protocol* due to its header magic.

## BF protocol packets
I'm a big fan of [Kaitai Struct](https://kaitai.io/) for creating packet definitions and easy parsing so I created a KSY file that defines the main packets used in the lobby.

```yaml
meta:
  id: bf_packet
  endian: le
seq:
  - id: header
    type: header
  - id: body
    type:
      switch-on: header.type
      cases:
        'packet_type::discover': discover_body
        'packet_type::session_info': session_info_body
        'packet_type::request_join': request_join_body
        'packet_type::confirm_join': confirm_join_body
        'packet_type::leave_session': leave_session_body
        'packet_type::chat': chat_body
        'packet_type::datagram': datagram_body
        'packet_type::session_players': session_players_body
        'packet_type::acknowledge': acknowledge_body
        'packet_type::host_change': host_change_body
        'packet_type::destroy_player': destroy_player_body
        'packet_type::add_player': add_player_body
types:
    header:
      seq:
        - id: magic
          contents: [0xBF]
        - id: type
          type: u1
          enum: packet_type
    add_player_body:
      seq:
        - id: pad
          size: 19
        - id: max_players
          type: u4
        - id: current_players
          type: u4
        - id: pad2
          size: 16
        - id: game_guid
          size: 16
        - id: session_guid
          size: 16
        - id: player_list
          type: player_info
    datagram_body:
      seq:
        - id: pad
          size: 1
        - id: sender_slot
          type: u4
        - id: destination_slot
          type: u4
          enum: receiver_type
        - id: len
          type: u2
        - id: message
          type: datagram
          size: len
    chat_body:
      seq:
        - id: pad
          size: 1
        - id: sender_slot
          type: u4
        - id: destination_slot
          type: u4
          enum: receiver_type
        - id: len
          type: u2
        - id: message
          type: str
          size: len
          encoding: UTF-16
    discover_body:
      seq:
        - id: padding
          size: 11
        - id: game_guid
          size: 16
    session_info_body:
      seq:
        - id: padding
          size: 11
        - id: session_desc
          type: session_desc
    request_join_body:
      seq:
        - id: padding
          size: 15
        - id: game_guid
          size: 16
        - id: session_guid
          size: 16
        - id: player_guid
          size: 16
        - id: player_name
          type: str
          size: 32
          encoding: UTF-16
        - id: password
          type: str
          size: 64
          encoding: UTF-16
    confirm_join_body:
      seq:
        - id: padding
          size: 15
        - id: game_guid
          size: 16
        - id: session_guid
          size: 16
        - id: player_guid
          size: 16
        - id: player_id
          type: u4
        - id: host_id
          type: u4
        - id: max_players
          type: u4
        - id: current_players
          type: u4
        - id: padding2
          size: 16
    destroy_player_body:
      seq:
      - id: padding
        size: 15
      - id: packet_id
        type: u4
      - id: max_players
        type: u4
      - id: current_players
        type: u4
      - id: padding2
        size: 16
      - id: game_guid
        size: 16
      - id: session_guid
        size: 16
      - id: padding3
        size: 16
      - id: player_id
        type: u4
    leave_session_body:
      seq:
        - id: padding
          size: 43
        - id: game_guid
          size: 16
        - id: session_guid
          size: 16
        - id: player_guid
          size: 16
        - id: player_id
          type: u4
    session_players_body:
      seq:
        - id: pad
          size: 11
        - id: packet_id
          type: u4
        - id: player_id
          type: u4
        - id: max_players
          type: u4
        - id: current_players
          type: u4
        - id: pad2
          size: 16
        - id: player_list_len
          type: u4
        - id: player_list
          type: player_info
          repeat: expr
          repeat-expr: player_list_len
        - id: pad3
          size-eos: true
    acknowledge_body:
      seq:
        - id: pad
          size: 1
        - id: sender_slot
          type: u4
        - id: destination_slot
          type: u4
          enum: receiver_type
        - id: pad2
          size: 2
        - id: sender_id
          type: u4
        - id: packet_id
          type: u4
        - id: pad3
          size-eos: true
    host_change_body:
      seq:
        - id: body
          size: 15
        - id: unknown
          type: u4
        - id: session_flags
          type: u4
        - id: old_host_id
          type: u4
        - id: max_players
          type: u4
        - id: current_players
          type: u4
        - id: unknown2
          type: u4
        - id: last_player_id
          type: u4
        - id: unknown3
          size: 8
        - id: game_guid
          size: 16
        - id: session_guid
          size: 16
        - id: new_host_name
          type: str
          size: 14
          encoding: UTF-16
        - id: pad
          size: 18
        - id: new_host_id
          type: u4
        - id: pad2
          size: 18
        - id: new_host_ip
          size: 4
        - id: new_host_port
          type: u2be
        - id: new_host_guid
          size: 16
        - id: last_player_id2
          type: u4
        - id: pad3
          size-eos: true
    player_info:
      seq:
        - id: name
          type: str
          size: 32
          encoding: UTF-16
        - id: id
          type: u4
        - id: unknown
          type: u4
        - id: unknown2
          type: u4
        - id: unknown3
          type: u4
        - id: unknown4
          type: u4
        - id: flags
          type: u1
        - id: slot
          type: u1
        - id: ip
          size: 4
        - id: port
          type: u2be
        - id: guid
          size: 16
        - id: pad
          size: 3
    datagram:
      seq:
        - id: cmd
          type: u1
        - id: value
          size-eos: true
        
    session_desc:
      seq:
        - id: game_version
          type: u4
        - id: session_guid
          size: 16
        - id: game_guid
          size: 16
        - id: max_players
          type: u4
        - id: current_players
          type: u4
        - id: unknown2
          size: 16
        - id: session_flags
          type: u4
        - id: language_id
          type: u4
        - id: unknown4
          type: u4
        - id: unknown5
          type: u4
        - id: unknown6
          type: u4
        - id: port
          type: u2be
        - id: socket
          type: u4
        - id: ip
          size: 4
        - id: padding
          size: 10
        - id: session_name
          type: str
          size: 64
          encoding: UTF-16

enums:
  packet_type:
    1: add_player
    3: datagram
    4: chat
    5: discover
    6: session_info
    7: request_join
    8: confirm_join
    9: destroy_player
    10: leave_session
    11: session_players
    12: acknowledge
    15: host_change
  receiver_type:
    0xFFFFFFFF: broadcast
    0xFFFFFFFE: host
```

And here's an example of each of the packets parsed by Kaitai and some comments about them.

### Add Player packet
Informs players that a new player joined the session.
{{img(id="img/add_player_packet.png" class="textCenter")}}

### Datagram packet
A wrapper to in-game related packets that get redirected to the main executable for interpreting.
{{img(id="img/datagram_packet.png" class="textCenter")}}

### Chat packet
A chat message that can be directed at a player, at the host or broadcast.
{{img(id="img/chat_packet.png" class="textCenter")}}

### Discover packet
Anounces that the player is looking for a session to join.
{{img(id="img/discover_packet.png" class="textCenter")}}

### Session Information packet
Basically contains the *SESSIONDESC* struct letting the player know about a possible session to join.
{{img(id="img/session_info_packet.png" class="textCenter")}}

### Request Join packet
Used to request the host to join a session, also contains a password if needed.
{{img(id="img/request_join_packet.png" class="textCenter")}}

### Confirm Join packet
Confirms that the player can join the session and gives the player information related to its status in the session.
{{img(id="img/confirm_join_packet.png" class="textCenter")}}

### Destroy Player packet
Tells players in a session that a player left and should be removed from their list.
{{img(id="img/destroy_player_packet.png" class="textCenter")}}

### Leave Session packet
Used to request the host to leave a session.
{{img(id="img/leave_session_packet.png" class="textCenter")}}

### Session Players packet
Gives a newly joined player information of the other players in the session. It is basically an array of *PLAYERDESC* structs.
{{img(id="img/session_players_packet.png" class="textCenter")}}

### Acknowledge packet
Acknowledges the reception of some packets like *Destroy Player* or *Session Players*.
{{img(id="img/acknowledge_packet.png" class="textCenter")}}

### Host Change packet
Informs players in a session that the host has changed and gives information of the new host.
{{img(id="img/host_change_packet.png" class="textCenter")}}

## Communication flow

Finally, now that we know about the packets used by this protocol let's show some of the most common communication flows that can happen in a lobby.

### Joining a session
{{img(id="img/populous3_flow_join_session.png" class="textCenter")}}

### Leaving a session
{{img(id="img/populous3_flow_leave_session.png" class="textCenter")}}

### Host leaving a session
{{img(id="img/populous3_flow_host_change.png" class="textCenter")}}

We now have a pretty good idea of how all the lobby related functionality works.

That's it for now :). I will probably write another post about how to exploit some vulnerabilities I found so stay tuned!
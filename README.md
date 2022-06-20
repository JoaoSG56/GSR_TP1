## Manager
lê oid a pedir
constroi packet

Se não estiver autenticado *(Autenticação)
    envia pedido de autenticação
    espera pela resposta
    autentica-se
    
envia
espera pela resposta
imprime resposta
 
## Agent
se primeiro oid == .3.3.3 -> procurar na MIBsec
else -> procurar na 



## Packet
Packet: HEADER|PAYLOAD

HEADER: TYPE$SRC
TYPE: GET-0 // get
TYPE: GET-1 // get-next
TYPE: requestAuth
TYPE: finalizeAuth

PAYLOAD: special;oid;oid;oid;checksum
special : 
* .3.3.3 MIB 
* .1.1.1 GET
* .2.2.2 GET-NEXT


## MIB
### MIBsec
* status :
    1. received - quando recebe o request
    2. ~~sent     - quando é enviado o pedido para a MIB~~
    3. ready    - quando a resposta ao pedido já chegou
    4. invalid  - quando a resposta ao pedido se encontra inválida : ttl < 0 && ttl > delThreshold
    5. deleted  - quando ttl == delThreshold
    6. None     - linha removida quando ttl < delThreshold

### MIB de autenticação
Address | state | TTL
---|---|---
('127.0.0.1',12) | 'authenticated' | 30
                   'expired'
* state:
    * expired - quando autenticação já não é válida. Próximo pedido a receber é pedido de request
    * requested - quando recebe um pedido de request de autenticação. Agent cria segredo, encripta-o com o segredo recebido, e coloca state a 'sent'
    * sent - segredo criado pelo agent enviado. Próximo pedido a ser recebido terá de ser um 'finalize' ou um 'request'
    * valid



## Tipos de msg
### Manager -> Agent
1. requestAuth
1. finalizeAuth
1. GET-0/1

### Agent -> Manager
1. response
1. requestAuth
1. invalidAuth - autenticação inválida (palavra pass inválida)
1. expiredAuth - autenticação expirada (não tem entrada ou ttl expirou)
1. successAuth

### Ordem de mensagem normal
requestAuth : Manager -> Agent
requestAuth : Agent -> Manager
finalize : Manager -> Agent
successAuth : Agent -> Manager
GET-0/1 : Manager -> Agent
response : Agent -> Manager
.
.
.
GET-0/1 : Manager -> Agent
expiredAuth : Agent -> Manager

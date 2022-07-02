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

HEADER: TYPE$SRC$CHECKSUM
SRC = USER
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

Address = \[User,('127.0.0.1',12)\]
* state:
    * expired - quando autenticação já não é válida. Próximo pedido a receber é pedido de request
    * requested - quando recebe um pedido de request de autenticação. Agent cria segredo, encripta-o com o segredo recebido, e coloca state a 'sent'
    * sent - segredo criado pelo agent enviado. Próximo pedido a ser recebido terá de ser um 'finalize' ou um 'request'
    * valid
    * invalid
Expired/invalid -> authenticating -> authenticated
     quando é recebido pedido    quando é recebido pedido
           "requestAuth"             finalize e é successful


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
1. invalidMessage - bad checksum

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


## Feito:
* adicionar checksum / hash - DONE
    * implementado no SET - DONE
    * falta verificação nos outros - DONE
* mudar source como sendo uma string - Done
    * implementar mib de string -> key
    * 
## Por fazer:

* implementar assincronia
    * thread-A continuamente a receber de servidor, a usar metódos de envio e imprimir no ecrâ
    * thread-B a ler do cliente e a adicionar numa queue de pedidos, que vai ser lida pela thread-A. Enviar sinal quando adiciona um pedido
    * thread-C? thread A passa só a receber pedidos do servidor e imprimir no ecrã. Thread C contém uma queue de envio para servidor, tanto da thread A como da thread B 

* adicionar outras medidas de segurança
    * quando várias mensagens são corrompidas
    * quando ocorre uma autenticação falhada
    * user inválido da mesma conexão

* adicionar mib's diferentes

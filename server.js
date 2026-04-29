<script>
const API_URL = "https://SEU-BACKEND.onrender.com";

async function login() {
  const wallet = document.getElementById("wallet").value;
  const result = document.getElementById("result");

  try {
    // 1. pede desafio
    const c = await fetch(`${API_URL}/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ wallet })
    });

    const challenge = await c.json();

    // ⚠️ aqui normalmente você assinaria com MetaMask
    // para simplificar, vou usar login antigo direto:

    const v = await fetch(`${API_URL}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet,
        message: challenge.message,
        signature: "0xFAKE_FOR_TEST" // precisa MetaMask na versão real
      })
    });

    const data = await v.json();
    result.innerText = JSON.stringify(data, null, 2);

  } catch (err) {
    result.innerText = "Erro: " + err.message;
  }
}
</script>






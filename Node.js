app.post("/spin", (req, res) => {

  let coins = getUserCoins(req.user);

  if(coins < 10){
    return res.json({error: "sem saldo"});
  }

  coins -= 10;

  let win = Math.random() <= 0.3;

  let result;

  if(win){
    let card = randomCard();
    result = generateWin(card);
    coins += 30;
  } else {
    result = generateLose();
  }

  updateCoins(req.user, coins);

  res.json({
    result,
    coins,
    win
  });
});

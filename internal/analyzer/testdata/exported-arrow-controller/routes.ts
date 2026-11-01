export const transfer = async (req: Request, res: Response): Promise<void> => {
  await processTransfer(req.body);
};

export const status = function(req: Request, res: Response) {
  res.send("ok");
};

function processTransfer(input) {}

app.post("/transfer", transfer);
app.get("/status", status);

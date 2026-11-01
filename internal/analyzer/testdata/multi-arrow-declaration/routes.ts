function processTransfer(input: unknown) {}
function loadStatus() {}

const helper = () => loadStatus(), transfer = async (req: Request, res: Response) => {
  await processTransfer(req.body);
};

app.post("/transfer", transfer);
app.get("/status", loadStatus);

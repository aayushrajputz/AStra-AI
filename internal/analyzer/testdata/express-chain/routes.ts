const router = express.Router();

function readWidget(req, res) {}
function createWidget(req, res) {}

router.route("/widgets")
  .get(readWidget)
  .post(createWidget);

app.use("/api", router);

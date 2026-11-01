@Controller("accounts")
export class AccountsController {
  private readonly accounts = new AccountsService();

  @Get(":id")
  getAccount(req, res) {
    return this.accounts.findOne(req.params.id);
  }
}

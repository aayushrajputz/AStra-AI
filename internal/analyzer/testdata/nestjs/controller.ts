@Controller("users")
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get(":id")
  getUser(req, res) {
    return this.users.findOne(req.params.id);
  }

  @Post()
  createUser(req, res) {
    return this.users.create(req.body);
  }

  @Put(":id")
  updateUser(req, res) {
    return this.users.update(req.params.id);
  }

  @Delete(":id")
  deleteUser(req, res) {
    return this.users.remove(req.params.id);
  }
}

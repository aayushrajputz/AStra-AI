export class AccountsService {
  findOne(id: string) {
    return database.find(id);
  }
}

export function fetchUser(id: string) {
  return database.find(id);
}

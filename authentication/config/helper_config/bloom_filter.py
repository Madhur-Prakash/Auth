import mmh3
import math


class CountingBloomFilter:
    def __init__(self, capacity: int, error_rate: float):
        self.capacity = capacity
        self.error_rate = error_rate
        self.size = self._get_size(capacity, error_rate)
        self.hash_count = self._get_hash_count(self.size, capacity)
        self.array = [0] * self.size

    def _get_size(self, n, p):
        # m = -(n * ln(p)) / (ln(2)^2)
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    def _get_hash_count(self, m, n):
        # k = (m/n) * ln(2)
        k = (m / n) * math.log(2)
        return int(k)

    def _get_hashes(self, item: str):
        return [mmh3.hash(item, seed) % self.size for seed in range(self.hash_count)]

    def add(self, item: str):
        for index in self._get_hashes(item):
            self.array[index] += 1

    def remove(self, item: str):
        if not self.contains(item):
            return False
        for index in self._get_hashes(item):
            self.array[index] -= 1
        return True

    def contains(self, item: str) -> bool:
        return all(self.array[index] > 0 for index in self._get_hashes(item))


# def delete_user(email: str, phone: str):
#     removed_email = email_filter.remove(email)
#     removed_phone = phone_filter.remove(phone)
#     if removed_email and removed_phone:
#         print("User deleted and Bloom filter cleaned.")
#     else:
#         print("User was not in Bloom filter.")
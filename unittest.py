import unittest

from app import app


class TestApp(unittest.TestCase):

    def test_home_route(self):
        client = app.test_client()
        response = client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Version', response.data.decode())
        self.assertIn('ModuleVersion', response.data.decode())

    def test_check_route(self):
        client = app.test_client()
        response = client.get('/check')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode(), 'Ok')


    def test_accessTkn_esia_route(self):
        client = app.test_client()
        response = client.post('/accessTkn_esia', json={'api_key': 'my api key'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue('accessTkn' in response.json())

    def test_order_route(self):
        client = app.test_client()
        response = client.post('/order', json={'api_key': 'my api key'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue('orderId' in response.json())

    def test_push_route(self):
        client = app.test_client()
        response = client.post('/push', json={'api_key': 'my api key'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue('pushId' in response.json())

    def test_push_chunked_route(self):
        client = app.test_client()
        response = client.post('/push/chunked', json={'api_key': 'my api key'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue('pushId' in response.json())

    def test_status_route(self):
        client = app.test_client()
        response = client.post('/status', json={'api_key': 'my api key'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue('orderId' in response.json())

if __name__ == '__main__':
    unittest.main()

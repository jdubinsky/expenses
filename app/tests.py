from django.test import TestCase
from django.test.client import Client, RequestFactory
from app.views import ListExpensesView
from app.models import Expenses

class ExpensesViewTests(TestCase):
	""" Expenses view tests """

	def test_users_in_context(self):
		client = Client()
		response = client.get('/')

		self.assertEquals(list(response.context['object_list']), [])

		Expenses.objects.create(name='foo')
		response = client.get('/')
		self.assertEquals(response.context['object_list'].count(), 1)

	def test_users_in_context_req_factory(self):
		factory = RequestFactory()
		req = factory.get('/')

		response = ListExpensesView.as_view()(req)
		self.assertEquals(list(response.context_data['object_list']), [])

		Expenses.objects.create(name='foo')
		response = ListExpensesView.as_view()(request)
		self.assertEquals(response.context_data['object_list'].count(), 1)


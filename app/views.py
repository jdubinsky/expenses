from django.shortcuts import render, render_to_response
from django.views.generic import View, ListView, CreateView, UpdateView
from app.models import Expenses, Users
from django.core.urlresolvers import reverse
from django import forms

class UsersForm(forms.Form):
    #users = forms.ModelChoiceField(queryset=Users.objects.all().values_list('id', 'name'))
    users = forms.ModelChoiceField(queryset=Users.objects.values_list('name', flat=True))

class ListUsersView(ListView):
    # model = Expenses
    model = Users
    template_name = 'users_list.html'

class CreateUsersView(CreateView):
    model = Users
    template_name = 'create_users.html'
    fields = ['name']

    def get_success_url(self):
        return reverse('users-list-user')

class UpdateUsersView(UpdateView):
    model = Users
    template_name = 'edit_users.html'
    fields = ['name']

    def get_success_url(self):
        return reverse('users-list-user')

class ListExpensesView(ListView):
    model = Expenses
    template_name = 'expenses_list.html'

    def get_context_data(self, **kwargs):
        ctx = super(ListExpensesView, self).get_context_data(**kwargs)
        ctx['users'] = Users.objects.all()
        return ctx

class CreateExpensesView(CreateView):
    model = Expenses
    template_name = 'create_expenses.html'
    # fields = ['lender', 'lendee', 'amount', 'reason', 'timestamp']
    fields = '__all__'

    def get_context_data(self, **kwargs):
        ctx = super(CreateExpensesView, self).get_context_data(**kwargs)
        ctx['users'] = Users.objects.all()
        return ctx

    def users(request):
        # users = Users.objects.all()
        form = UsersForm(request.POST)
        # if request.method == 'POST':
        #     selected_item = get_object_or_404(User, pk=request.POST.get('expenses_list'))

        return render_to_response ('create_expenses.html', {'form' : form},)

    def get_success_url(self):
        return reverse('expenses-list')

class UpdateExpensesView(UpdateView):
    model = Expenses
    template_name = 'edit_expenses.html'
    #fields = ['lender', 'lendee', 'amount', 'reason', 'timestamp']
    fields = '__all__'

    def get_success_url(self):
        return reverse('expenses-list')

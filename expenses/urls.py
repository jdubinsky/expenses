from django.conf.urls import patterns, include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
import app.views

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'expenses.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    # url(r'^admin/', include(admin.site.urls)),
    url(r'^$', app.views.ListExpensesView.as_view(),
        name='expenses-list'),
    url(r'^new-expense$', app.views.CreateExpensesView.as_view(),
        name='expenses-new-expense'),
    url(r'^edit-expense/(?P<pk>\d+)/$', app.views.UpdateExpensesView.as_view(),
        name='expenses-edit-expense'),
    url(r'^list-user$', app.views.ListUsersView.as_view(),
    	name='users-list-user'),
    url(r'^new-user$', app.views.CreateUsersView.as_view(),
    	name='users-new-user'),
    url(r'^edit-user/(?P<pk>\d+)/$', app.views.UpdateUsersView.as_view(),
    	name='users-edit-user'),
)

urlpatterns += staticfiles_urlpatterns()
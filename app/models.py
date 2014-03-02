from django.db import models
from django.core.urlresolvers import reverse

# model for users
# auto increment user id (made automatically by django)
# varchar name
class Users(models.Model):
    name = models.CharField(
        max_length=255,
    )

    def get_absolute_url(self):
        return reverse('users-list', kwargs={'pk': self.pk})

    def __unicode__(self):
        return "%s" % self.name

# model for keeping track of finances
# user1 owes user2 $x for reason y
class Expenses(models.Model):
    lender = models.ForeignKey(
        Users,
        related_name='lender',
    )
    lendee = models.ForeignKey(
        Users,
        related_name='lendee',
    )
    amount = models.DecimalField(
        max_digits=8,
        decimal_places=2,
    )
    reason = models.CharField(
        max_length=255,
    )
    timestamp = models.DateTimeField(
        auto_now=True,
    )




    def get_absolute_url(self):
        return reverse('expenses-list', kwargs={'pk': self.pk})

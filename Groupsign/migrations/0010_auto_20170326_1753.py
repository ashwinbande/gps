# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-26 12:23
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Groupsign', '0009_user_sign_joined'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='sign_joined',
            new_name='sign_created',
        ),
    ]

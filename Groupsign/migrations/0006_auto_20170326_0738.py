# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-26 02:08
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Groupsign', '0005_delete_security_parameters'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='Ai',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='Ei',
            field=models.TextField(null=True),
        ),
    ]

# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-26 02:59
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Groupsign', '0007_auto_20170326_0759'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user_keys',
            name='user',
        ),
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
        migrations.DeleteModel(
            name='User_keys',
        ),
    ]
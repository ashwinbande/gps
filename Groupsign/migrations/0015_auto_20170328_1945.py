# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-28 14:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Groupsign', '0014_auto_20170327_0205'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='Ai',
            field=models.CharField(blank=True, max_length=1024, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='Ei',
            field=models.CharField(blank=True, max_length=1024, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='Xi',
            field=models.CharField(blank=True, max_length=1024, null=True),
        ),
    ]
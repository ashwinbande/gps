# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-26 15:01
from __future__ import unicode_literals

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('Groupsign', '0011_auto_20170326_1803'),
    ]

    operations = [
        migrations.AddField(
            model_name='messeges',
            name='time',
            field=models.DateTimeField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
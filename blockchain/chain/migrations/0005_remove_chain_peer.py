# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-11 01:42
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blockchain', '0004_chain_peer'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chain',
            name='peer',
        ),
    ]

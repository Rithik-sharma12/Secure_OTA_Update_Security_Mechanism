'use client';

import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { toast } from 'sonner';
import { ArrowRightLeft, ShieldCheck } from 'lucide-react';

// 1. Client Interface Layer: Client-side validation mirroring API requirements
const formSchema = z.object({
  sourceAccountId: z.string().min(1, 'Source account is required'),
  destinationAccountId: z.string().min(1, 'Destination account is required'),
  amount: z.coerce.number().positive('Amount must be greater than zero'),
});

type TransferFormValues = z.infer<typeof formSchema>;

export default function TransferGatewayPage() {
  const { register, handleSubmit, formState: { errors, isSubmitting }, reset } = useForm<TransferFormValues>({
    resolver: zodResolver(formSchema),
  });

  const onSubmit = async (data: TransferFormValues) => {
    try {
      // Generate idempotency key for this specific submission attempt
      const idempotencyKey = crypto.randomUUID();

      const response = await fetch('/api/transfers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer valid-token', // Mock Token
        },
        body: JSON.stringify({ ...data, idempotencyKey }),
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error?.message || 'Transfer failed');
      }

      toast.success('Transfer Successful', {
        description: `Successfully transferred $${data.amount} to ${data.destinationAccountId}`,
      });
      reset();
    } catch (error: any) {
      toast.error('Transaction Error', {
        description: error.message,
      });
    }
  };

  return (
    <div className="max-w-xl mx-auto mt-12 p-6 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-xl shadow-sm">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-lg">
          <ShieldCheck size={24} />
        </div>
        <div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">SecureX Transfer Gateway</h1>
          <p className="text-sm text-zinc-500">Encrypted and idempotent financial routing</p>
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
        <div className="space-y-2">
          <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Source Account ID</label>
          <input 
            {...register('sourceAccountId')} 
            className="w-full p-2 border border-zinc-300 dark:border-zinc-800 rounded-md bg-transparent"
            placeholder="e.g. ACC-123"
          />
          {errors.sourceAccountId && <span className="text-xs text-red-500">{errors.sourceAccountId.message}</span>}
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Destination Account ID</label>
          <input 
            {...register('destinationAccountId')} 
            className="w-full p-2 border border-zinc-300 dark:border-zinc-800 rounded-md bg-transparent"
            placeholder="e.g. ACC-456"
          />
          {errors.destinationAccountId && <span className="text-xs text-red-500">{errors.destinationAccountId.message}</span>}
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Amount ($)</label>
          <input 
            type="number"
            step="0.01"
            {...register('amount')} 
            className="w-full p-2 border border-zinc-300 dark:border-zinc-800 rounded-md bg-transparent"
            placeholder="0.00"
          />
          {errors.amount && <span className="text-xs text-red-500">{errors.amount.message}</span>}
        </div>

        <button 
          disabled={isSubmitting}
          className="w-full flex justify-center items-center gap-2 py-3 bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 rounded-md font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {isSubmitting ? 'Processing Securely...' : 'Initiate Transfer'}
          {!isSubmitting && <ArrowRightLeft size={18} />}
        </button>
      </form>
    </div>
  );
}
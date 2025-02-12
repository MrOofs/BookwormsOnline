using BookwormsOnline.Data;
using BookwormsOnline.Models;
using System.Threading.Tasks;

namespace BookwormsOnline.Services
{
    public interface IAuditLogger
    {
        Task LogAsync(string userId, string activity);
    }

    public class AuditLogger : IAuditLogger
    {
        private readonly ApplicationDbContext _context;

        public AuditLogger(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task LogAsync(string userId, string activity)
        {
            var log = new AuditLog
            {
                UserId = userId,
                Activity = activity,
                Timestamp = DateTime.UtcNow
            };

            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();
        }
    }
}
